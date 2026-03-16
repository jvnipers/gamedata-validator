#!/usr/bin/env python3
"""
Converts a SourceMod/Metamod .games.txt KeyValues file into the
signatures.jsonc format consumed by swiftly-solution/gamedata-validator.

Usage:
    python convert_kv_to_jsonc.py \
        --input  gamedata/cs2kz-core.games.txt \
        --output cache/signatures.jsonc

The output format per entry is:
    "SignatureName": {
        "lib":     "server",   // or whatever library
        "windows": "40 53 57 ? ? ? ?",
        "linux":   "55 48 89 E5 ..."
    }

Notes:
- \x2A is the wildcard byte in .games.txt → converted to ?
- Any pattern containing [...] is truncated upstream and will be
  skipped with a warning.
- Only entries under the "Signatures" block are converted.
  "Offsets" blocks are written to a separate _offsets.json file
  for reference (the swiftly validator does not scan offsets).
"""

import re
import json
import argparse
import sys
from pathlib import Path

_TOKEN_RE = re.compile(
    r'"((?:[^"\\]|\\.)*)"' # quoted string
    r'|(//.*)$' # line comment
    r'|([{}])',  # brace
    re.MULTILINE,
)

def tokenize(text: str):
    """Yield (type, value) tokens from a KeyValues text."""
    for m in _TOKEN_RE.finditer(text):
        if m.group(1) is not None:
            yield ('str', m.group(1))
        elif m.group(2) is not None:
            pass  # skip comments
        elif m.group(3) is not None:
            yield ('brace', m.group(3))


def parse_kv(tokens) -> dict | str:
    """
    Recursively parse a KeyValues block.
    Assumes the opening '{' has already been consumed (or we're at top-level).
    Returns a dict.
    """
    result = {}
    it = iter(tokens)

    def _next():
        try:
            return next(it)
        except StopIteration:
            return None

    # We consume from a shared list passed in, so use a generator approach.
    return result


def parse_kv_full(text: str) -> dict:
    """Full parse of a KeyValues document into nested dicts."""
    tokens = list(tokenize(text))
    pos = 0

    def peek():
        if pos < len(tokens):
            return tokens[pos]
        return None

    def consume():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_block() -> dict:
        result = {}
        while pos < len(tokens):
            tok = peek()
            if tok is None:
                break
            if tok == ('brace', '}'):
                consume()
                break
            if tok[0] != 'str':
                consume()
                continue
            key = consume()[1]
            nxt = peek()
            if nxt is None:
                break
            if nxt == ('brace', '{'):
                consume()  # eat '{'
                result[key] = parse_block()
            elif nxt[0] == 'str':
                result[key] = consume()[1]
            else:
                consume()
        return result

    # Top-level: expect a key then a block
    tok = peek()
    if tok and tok[0] == 'str':
        consume()  # "Games"
    if peek() == ('brace', '{'):
        consume()  # opening {
    return parse_block()


# ---------------------------------------------------------------------------
# Signature conversion helpers
# ---------------------------------------------------------------------------

WILDCARD_BYTE = '2A'  # \x2A is the wildcard in .games.txt format


def games_txt_sig_to_spaced_hex(raw: str) -> str | None:
    """
    Convert a .games.txt signature string like:
        \x40\x53\x57\x2A\x2A\x2A\x2A\x48\x8B\xD9\x8B\xFA
    Into space-separated hex with ? for wildcards:
        40 53 57 ? ? ? ? 48 8B D9 8B FA

    Returns None if the pattern is truncated (contains '[...]').
    """
    if '[...]' in raw:
        return None  # truncated pattern, skip

    # Handle both \xNN and \\xNN (escaped in the file)
    raw_clean = raw.replace('\\\\x', '\\x')

    bytes_out = []
    i = 0
    while i < len(raw_clean):
        if raw_clean[i] == '\\' and i + 1 < len(raw_clean) and raw_clean[i + 1] == 'x':
            hex_byte = raw_clean[i + 2: i + 4].upper()
            if hex_byte == WILDCARD_BYTE:
                bytes_out.append('?')
            else:
                bytes_out.append(hex_byte)
            i += 4
        else:
            # Literal character — treat as raw byte
            bytes_out.append(f'{ord(raw_clean[i]):02X}')
            i += 1

    if not bytes_out:
        return None

    return ' '.join(bytes_out)

def convert(games_txt_path: Path, output_jsonc: Path, output_offsets: Path):
    text = games_txt_path.read_text(encoding='utf-8')
    tree = parse_kv_full(text)

    # tree structure: { "csgo": { "Signatures": {...}, "Offsets": {...} } }
    # Find the game block (usually "csgo")
    game_block = None
    for key, val in tree.items():
        if isinstance(val, dict):
            game_block = val
            break

    if game_block is None:
        print("ERROR: Could not find top-level game block in the .games.txt file.")
        sys.exit(1)

    signatures_block = game_block.get('Signatures', {})
    offsets_block    = game_block.get('Offsets', {})

    output_sigs = {}
    skipped     = []

    for sig_name, sig_data in signatures_block.items():
        if not isinstance(sig_data, dict):
            continue

        library  = sig_data.get('library', 'server')
        windows  = sig_data.get('windows', '')
        linux    = sig_data.get('linux', '')

        win_hex = games_txt_sig_to_spaced_hex(windows) if windows else None
        lin_hex = games_txt_sig_to_spaced_hex(linux)   if linux   else None

        if win_hex is None and lin_hex is None:
            skipped.append((sig_name, 'both patterns missing or truncated'))
            continue

        if win_hex is None:
            skipped.append((sig_name, 'windows pattern truncated/missing — linux only'))
        if lin_hex is None:
            skipped.append((sig_name, 'linux pattern truncated/missing — windows only'))

        entry = {'lib': library}
        if win_hex:
            entry['windows'] = win_hex
        if lin_hex:
            entry['linux'] = lin_hex
        # Carry through allow_multi_match flag if present
        if sig_data.get('allow_multi_match') == '1':
            entry['allow_multi_match'] = True

        output_sigs[sig_name] = entry

    output_offsets_data = {}
    for offset_name, offset_data in offsets_block.items():
        if not isinstance(offset_data, dict):
            continue
        entry = {}
        if 'windows' in offset_data:
            entry['windows'] = int(offset_data['windows'])
        if 'linux' in offset_data:
            entry['linux'] = int(offset_data['linux'])
        output_offsets_data[offset_name] = entry

    # .jsonc: write with // comment header so it's valid commentjson input
    jsonc_lines = [
        '// Auto-generated by convert_kv_to_jsonc.py',
        f'// Source: {games_txt_path.name}',
        '//',
        '// Format per entry:',
        '//   "SignatureName": { "lib": "server", "windows": "HH HH ?", "linux": "HH HH ?" }',
        '//',
    ]
    jsonc_lines.append(json.dumps(output_sigs, indent=2))
    output_jsonc.write_text('\n'.join(jsonc_lines), encoding='utf-8')

    output_offsets.write_text(
        json.dumps(output_offsets_data, indent=2),
        encoding='utf-8',
    )

    # ---- Summary -----------------------------------------------------------
    print(f"\nConverted {len(output_sigs)} signatures  →  {output_jsonc}")
    print(f"Exported  {len(output_offsets_data)} offsets     →  {output_offsets}")

    if skipped:
        print(f"\nSkipped / partial ({len(skipped)}):")
        for name, reason in skipped:
            print(f"   • {name}: {reason}")

def main():
    parser = argparse.ArgumentParser(
        description='Convert a Metamod .games.txt file to swiftly-validator signatures.jsonc'
    )
    parser.add_argument(
        '--input', '-i',
        default='cs2kz-core.games.txt',
        help='Path to the input .games.txt file (default: cs2kz-core.games.txt)',
    )
    parser.add_argument(
        '--output-signatures', '-os',
        default='cache/signatures.jsonc',
        help='Path for the output signatures.jsonc (default: cache/signatures.jsonc)',
    )
    parser.add_argument(
        '--offsets-output', '-oo',
        default='cache/offsets.json',
        help='Path for the exported offsets reference JSON (default: cache/offsets.json)',
    )
    args = parser.parse_args()

    input_path   = Path(args.input)
    output_path  = Path(args.output_signatures)
    offsets_path = Path(args.offsets_output)

    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)

    convert(input_path, output_path, offsets_path)


if __name__ == '__main__':
    main()
