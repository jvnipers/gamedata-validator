import json
import subprocess
import platform
import time
import hashlib
import shutil
import sys
import signal
import requests
import commentjson
import s2binlib

from pathlib import Path
from os import makedirs
from dotenv import load_dotenv
from steamchecker import CheckGameUpdates, GetSignature
from discord_notifier import notify_vfunc_results, notify_pattern_scan_results

sys.path.insert(0, str(Path(__file__).parent))
from convert_kv_to_jsonc import convert as convert_gamedata

load_dotenv()

import os

KZ_GAMEDATA_URL   = os.getenv(
    'KZ_GAMEDATA_URL',
    'https://raw.githubusercontent.com/KZGlobalTeam/cs2kz-metamod/master/gamedata/cs2kz-core.games.txt',
)
KZ_GAMEDATA_LOCAL = os.getenv('KZ_GAMEDATA_LOCAL', '')
POLL_INTERVAL     = int(os.getenv('POLL_INTERVAL', '60'))
SKIP_VFUNC        = os.getenv('SKIP_VFUNC', '0') == '1'

DATA_DIR         = Path('data')
OUTPUT_DIR       = Path('output')
CACHE_DIR        = Path('cache')
PUBLIC_FILE      = Path('public730.txt')

GAMES_TXT_CACHE  = CACHE_DIR / 'kz_gamedata_cache.games.txt'
SIGNATURES_JSONC = CACHE_DIR / 'kz_signatures.jsonc'
OFFSETS_JSON     = CACHE_DIR / 'kz_offsets.json'
HASH_CACHE_FILE  = CACHE_DIR / 'kz_gamedata.hash'

def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def fetch_kz_gamedata() -> str:
    if KZ_GAMEDATA_LOCAL:
        p = Path(KZ_GAMEDATA_LOCAL)
        if not p.exists():
            raise FileNotFoundError(f"KZ_GAMEDATA_LOCAL set but file not found: {p}")
        print(f"Using local gamedata file: {p}")
        return p.read_text(encoding='utf-8')

    print(f"Fetching gamedata from: {KZ_GAMEDATA_URL}")
    r = requests.get(KZ_GAMEDATA_URL, timeout=30)
    r.raise_for_status()
    return r.text


def kz_gamedata_fetch_and_check_changed() -> bool:
    """
    Fetches the gamedata, writes it to GAMES_TXT_CACHE, and returns True
    if it changed since the last run. Always writes the cache on success
    so that prepare_signatures_jsonc() always has a file to read.
    Returns False on fetch error (non-fatal).
    """
    try:
        text = fetch_kz_gamedata()
    except Exception as e:
        print(f"Could not fetch KZ gamedata: {e}")
        return False

    new_hash = sha256_of_text(text)
    old_hash = HASH_CACHE_FILE.read_text().strip() if HASH_CACHE_FILE.exists() else ''

    # Always write the cache so it's available for the converter
    GAMES_TXT_CACHE.write_text(text, encoding='utf-8')

    if new_hash == old_hash:
        return False

    HASH_CACHE_FILE.write_text(new_hash)
    print(f"KZ gamedata changed  (sha256: {new_hash[:16]}...)")
    return True


def prepare_signatures_jsonc():
    """Run the converter to regenerate kz_signatures.jsonc from the cached .games.txt."""
    if not GAMES_TXT_CACHE.exists():
        print(f"Cache file {GAMES_TXT_CACHE} does not exist - cannot convert.")
        return False
    print("Converting cs2kz-core.games.txt → kz_signatures.jsonc ...")
    convert_gamedata(GAMES_TXT_CACHE, SIGNATURES_JSONC, OFFSETS_JSON)
    return True


def download_depot(depot_id: int, workspace_name: str):
    executable = str(DATA_DIR / ('DepotDownloader.exe' if platform.system() == 'Windows' else 'DepotDownloader'))
    args = [
        '-app', '730',
        '-depot', str(depot_id),
        '-dir', f"{workspace_name}/binaries",
        '-filelist', str(DATA_DIR / 'files.txt'),
    ]
    command = [executable] + args
    print(f"Downloading depot {depot_id}: {' '.join(command)}")
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    print(stdout.decode())
    if stderr:
        print(f"  Depot {depot_id} stderr:\n{stderr.decode()}")


def download_depots(workspace_name: str):
    download_depot(2347771, workspace_name)
    download_depot(2347773, workspace_name)

def dump_vfunc_counts(os_name: str, workspace_name: str, sig: str) -> list:
    if SKIP_VFUNC:
        print(f"Skipping vtable scan (SKIP_VFUNC=1)")
        return []

    outputs = []
    classes_path = DATA_DIR / 'classes.json'
    if not classes_path.exists():
        print(f"{classes_path} not found, skipping vtable scan.")
        return []

    with open(classes_path) as f:
        classes = json.load(f)

    for class_info in classes:
        binary_name = class_info['name']
        for class_name in class_info['classes']:
            try:
                table_va    = s2binlib.find_vtable_va(binary_name, class_name)
                vfunc_count = s2binlib.get_vfunc_count(binary_name, class_name)
                outputs.append({
                    'class_name': class_name,
                    'vfunc_count': vfunc_count,
                    'va': f"{binary_name}.{hex(table_va)}",
                    'binary': binary_name,
                })
            except Exception as e:
                print(f"vtable {class_name} in {binary_name}: {e}")

    out_path = OUTPUT_DIR / sig / f'vfunc_counts_{os_name}.json'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outputs, indent=4))
    return outputs


def pattern_scan(os_name: str, sig: str) -> list:
    outputs = []

    if not SIGNATURES_JSONC.exists():
        print(f"{SIGNATURES_JSONC} not found - did conversion run?")
        return outputs

    with open(SIGNATURES_JSONC) as f:
        signatures = commentjson.load(f)

    total        = 0
    success      = 0
    failed_names = []

    for sig_name, sig_data in signatures.items():
        lib     = sig_data.get('lib', 'server')
        pattern = sig_data.get(os_name, '')

        if not pattern:
            continue

        total += 1
        try:
            match, count = s2binlib.pattern_scan(lib, pattern)
            entry = {
                'signature': sig_name,
                'va': f"{lib}.{hex(match)}",
                'count': count,
            }
            if sig_data.get('allow_multi_match'):
                entry['allow_multi_match'] = True
            outputs.append(entry)
            if count == 1:
                success += 1
            elif count == 0:
                failed_names.append(f"{sig_name} ({os_name})")
            else:
                if sig_data.get('allow_multi_match'):
                    success += 1  # intentional multi-match, count as success
                    print(f"  🔵 {sig_name} ({os_name}): {count} matches (allow_multi_match)")
                else:
                    print(f"  🟡 {sig_name} ({os_name}): {count} matches (ambiguous!)")
        except Exception as e:
            print(f"{sig_name} ({os_name}): {e}")
            outputs.append({'signature': sig_name, 'va': 'error', 'count': 0})
            failed_names.append(f"{sig_name} ({os_name})")

    print(f"{os_name}: {success}/{total} signatures found")
    if failed_names:
        print(f"Failed ({len(failed_names)}):")
        for n in failed_names:
            print(f"       • {n}")

    out_path = OUTPUT_DIR / sig / f'signatures_{os_name}.json'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outputs, indent=4))
    return outputs

def check_and_validate():
    gamedata_changed = kz_gamedata_fetch_and_check_changed()
    updated_depots = CheckGameUpdates(730)

    if not updated_depots and not gamedata_changed:
        print("No updates detected.")
        return

    if updated_depots:
        print(f"CS2 depot(s) updated: {updated_depots}")
    if gamedata_changed:
        print("KZ gamedata file updated.")

    sig       = GetSignature()
    workspace = f"workspace_{sig}"

    makedirs(OUTPUT_DIR / sig,        exist_ok=True)
    makedirs(f"{workspace}/binaries", exist_ok=True)

    binaries_path = Path(workspace) / 'binaries' / 'game'
    if updated_depots or not binaries_path.exists():
        print("Downloading CS2 binaries...")
        download_depots(workspace)
    else:
        print("Reusing existing binaries (only gamedata changed).")

    if gamedata_changed or not SIGNATURES_JSONC.exists():
        if not prepare_signatures_jsonc():
            print("Conversion failed, aborting this run.")
            return
    else:
        print("Reusing existing kz_signatures.jsonc.")

    vfunc_results = {}
    scan_results  = {}

    for os_name in ['windows', 'linux']:
        print(f"\nScanning [{os_name}] ...")
        s2binlib.initialize(f"./{workspace}/binaries/game", "csgo", os_name)
        vfunc_results[os_name] = dump_vfunc_counts(os_name, workspace, sig)
        scan_results[os_name]  = pattern_scan(os_name, sig)

    if not SKIP_VFUNC and any(vfunc_results.values()):
        notify_vfunc_results(vfunc_results, sig)
    notify_pattern_scan_results(scan_results, sig)

    latest = OUTPUT_DIR / 'latest'
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(OUTPUT_DIR / sig, latest)

    print(f"\nDone - results in output/{sig}/ and output/latest/")


if __name__ == '__main__':
    shutdown = False

    def _sigint_handler(sig, frame):
        global shutdown
        if shutdown:
            print("\nForced exit.")
            sys.exit(1)
        shutdown = True
        print("\nShutting down gracefully (Ctrl+C again to force) ...")

    signal.signal(signal.SIGINT, _sigint_handler)

    print("KZ Gamedata Validator started")
    print(f"Poll interval : {POLL_INTERVAL}s")
    print(f"Gamedata URL  : {KZ_GAMEDATA_LOCAL or KZ_GAMEDATA_URL}")
    print(f"Skip vfunc    : {SKIP_VFUNC}")
    print()

    while not shutdown:
        try:
            check_and_validate()
        except Exception as e:
            import traceback
            print(f"\nUnhandled error: {e}")
            traceback.print_exc()
        for _ in range(POLL_INTERVAL):
            if shutdown:
                break
            time.sleep(1)

    print("Exited.")
