import json
import subprocess
import platform
import re
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
from steamchecker import CheckGameUpdates, GetBuildId, GetSignature
from discord_notifier import notify_vfunc_results, notify_pattern_scan_results

sys.path.insert(0, str(Path(__file__).parent))
from convert_kv_to_jsonc import convert as convert_gamedata

load_dotenv()

import os

DEFAULT_GAMEDATA_URL = (
    "https://raw.githubusercontent.com/KZGlobalTeam/cs2kz-metamod"
    "/master/gamedata/cs2kz-core.games.txt"
)

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
SKIP_VFUNC = os.getenv("SKIP_VFUNC", "0") == "1"

DATA_DIR = Path("data")
OUTPUT_DIR = Path("output")
CACHE_DIR = Path("cache")
PUBLIC_FILE = CACHE_DIR / "public730.txt"

makedirs(CACHE_DIR, exist_ok=True)


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", name.lower())


def load_gamedata_sources() -> list:
    """
    Load gamedata sources from environment variables.

    Multi-source format:
        GAMEDATA_SOURCES=kz,movement
        KZ_GAMEDATA_URL=https://...
        KZ_GAMEDATA_LOCAL=/path/to/file
        MOVEMENT_GAMEDATA_URL=https://...

    _LOCAL wins over _URL for the same source.

    Legacy fallback when GAMEDATA_SOURCES is unset: a single source named "kz"
    built from KZ_GAMEDATA_URL / KZ_GAMEDATA_LOCAL.
    """
    names = [n.strip() for n in os.getenv("GAMEDATA_SOURCES", "").split(",")]
    names = [n for n in names if n]

    if names:
        entries = []
        for name in names:
            prefix = name.upper()
            url = os.getenv(f"{prefix}_GAMEDATA_URL", "")
            local = os.getenv(f"{prefix}_GAMEDATA_LOCAL", "")
            if not url and not local:
                print(
                    f"Warning: neither {prefix}_GAMEDATA_URL nor {prefix}_GAMEDATA_LOCAL "
                    f"is set, skipping source '{name}'"
                )
                continue
            entries.append((name, url, local))
    else:
        entries = [
            (
                "kz",
                os.getenv("KZ_GAMEDATA_URL", DEFAULT_GAMEDATA_URL),
                os.getenv("KZ_GAMEDATA_LOCAL", ""),
            )
        ]

    sources = []
    for name, url, local in entries:
        slug = _slugify(name)
        sources.append(
            {
                "name": name,
                "slug": slug,
                "url": url,
                "local": local,
                "games_txt": CACHE_DIR / f"{slug}_gamedata_cache.games.txt",
                "signatures": CACHE_DIR / f"{slug}_signatures.jsonc",
                "offsets": CACHE_DIR / f"{slug}_offsets.json",
                "hash": CACHE_DIR / f"{slug}_gamedata.hash",
            }
        )
    return sources


GAMEDATA_SOURCES = load_gamedata_sources()


def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def fetch_gamedata(source: dict) -> str:
    name = source["name"]
    if source["local"]:
        p = Path(source["local"])
        if not p.exists():
            raise FileNotFoundError(
                f"{name.upper()}_GAMEDATA_LOCAL set but file not found: {p}"
            )
        print(f"[{name}] Using local gamedata file: {p}")
        return p.read_text(encoding="utf-8")

    print(f"[{name}] Fetching gamedata from: {source['url']}")
    r = requests.get(source["url"], timeout=30)
    r.raise_for_status()
    return r.text


def gamedata_fetch_and_check_changed(source: dict) -> bool:
    """
    Fetches one source's gamedata, writes it to its .games.txt cache, and returns True if it changed since the last run.
    Always writes the cache on success
    so that prepare_signatures_jsonc() always has a file to read.
    Returns False on fetch error (non-fatal).
    """
    name = source["name"]
    try:
        text = fetch_gamedata(source)
    except Exception as e:
        print(f"[{name}] Could not fetch gamedata: {e}")
        return False

    new_hash = sha256_of_text(text)
    hash_file = source["hash"]
    old_hash = hash_file.read_text().strip() if hash_file.exists() else ""

    # Always write the cache so it's available for the converter
    source["games_txt"].write_text(text, encoding="utf-8")

    if new_hash == old_hash:
        return False

    hash_file.write_text(new_hash)
    print(f"[{name}] gamedata changed  (sha256: {new_hash[:16]}...)")
    return True


def prepare_signatures_jsonc(source: dict) -> bool:
    """Regenerate one source's signatures .jsonc from its cached .games.txt."""
    name = source["name"]
    if not source["games_txt"].exists():
        print(
            f"[{name}] Cache file {source['games_txt']} does not exist - cannot convert."
        )
        return False
    print(
        f"[{name}] Converting {source['games_txt'].name} → {source['signatures'].name} ..."
    )
    convert_gamedata(source["games_txt"], source["signatures"], source["offsets"])
    return True


def download_depot(depot_id: int, workspace_name: str):
    executable = str(
        DATA_DIR
        / (
            "DepotDownloader.exe"
            if platform.system() == "Windows"
            else "DepotDownloader"
        )
    )
    args = [
        "-app",
        "730",
        "-depot",
        str(depot_id),
        "-dir",
        f"{workspace_name}/binaries",
        "-filelist",
        str(DATA_DIR / "files.txt"),
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
    classes_path = DATA_DIR / "classes.json"
    if not classes_path.exists():
        print(f"{classes_path} not found, skipping vtable scan.")
        return []

    with open(classes_path) as f:
        classes = json.load(f)

    for class_info in classes:
        binary_name = class_info["name"]
        for class_name in class_info["classes"]:
            try:
                table_va = s2binlib.find_vtable_va(binary_name, class_name)
                vfunc_count = s2binlib.get_vfunc_count(binary_name, class_name)
                outputs.append(
                    {
                        "class_name": class_name,
                        "vfunc_count": vfunc_count,
                        "va": f"{binary_name}.{hex(table_va)}",
                        "binary": binary_name,
                    }
                )
            except Exception as e:
                print(f"vtable {class_name} in {binary_name}: {e}")

    out_path = OUTPUT_DIR / sig / f"vfunc_counts_{os_name}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outputs, indent=4))
    return outputs


def pattern_scan(os_name: str, sig: str, source: dict) -> list:
    outputs = []
    name = source["name"]
    signatures_file = source["signatures"]

    if not signatures_file.exists():
        print(f"[{name}] {signatures_file} not found - did conversion run?")
        return outputs

    with open(signatures_file) as f:
        signatures = commentjson.load(f)

    total = 0
    success = 0
    failed_names = []

    for sig_name, sig_data in signatures.items():
        lib = sig_data.get("lib", "server")
        pattern = sig_data.get(os_name, "")

        if not pattern:
            continue

        total += 1
        try:
            match, count = s2binlib.pattern_scan(lib, pattern)
            entry = {
                "signature": sig_name,
                "va": f"{lib}.{hex(match)}",
                "count": count,
            }
            if sig_data.get("allow_multi_match"):
                entry["allow_multi_match"] = True
            outputs.append(entry)
            if count == 1:
                success += 1
            elif count == 0:
                failed_names.append(f"{sig_name} ({os_name})")
            else:
                if sig_data.get("allow_multi_match"):
                    success += 1  # intentional multi-match, count as success
                    print(
                        f"🔵 [{name}] {sig_name} ({os_name}): {count} matches (allow_multi_match)"
                    )
                else:
                    print(
                        f"🟡 [{name}] {sig_name} ({os_name}): {count} matches (ambiguous!)"
                    )
        except Exception as e:
            print(f"[{name}] {sig_name} ({os_name}): {e}")
            outputs.append({"signature": sig_name, "va": "error", "count": 0})
            failed_names.append(f"{sig_name} ({os_name})")

    print(f"[{name}] {os_name}: {success}/{total} signatures found")
    if failed_names:
        print(f"[{name}] Failed ({len(failed_names)}):")
        for n in failed_names:
            print(f"       • {n}")

    out_path = OUTPUT_DIR / sig / f"signatures_{source['slug']}_{os_name}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outputs, indent=4))
    return outputs


def check_and_validate():
    if not GAMEDATA_SOURCES:
        print("No gamedata sources configured.")
        return

    changed = {s["name"]: gamedata_fetch_and_check_changed(s) for s in GAMEDATA_SOURCES}
    any_gamedata_changed = any(changed.values())

    updated_depots = CheckGameUpdates(730)

    if updated_depots is False:
        print("Steam PICS check failed (all retries exhausted).")
        if not any_gamedata_changed:
            print("No updates detected.")
            return
        updated_depots = []

    if not updated_depots and not any_gamedata_changed:
        print("No updates detected.")
        return

    if updated_depots:
        print(f"CS2 depot(s) updated: {updated_depots}")
    for name, did_change in changed.items():
        if did_change:
            print(f"Gamedata file updated: {name}")

    sig = GetSignature()
    workspace = f"workspace_{GetBuildId()}"

    makedirs(OUTPUT_DIR / sig, exist_ok=True)
    makedirs(f"{workspace}/binaries", exist_ok=True)

    binaries_path = Path(workspace) / "binaries" / "game"
    binaries_stale = bool(updated_depots) or not binaries_path.exists()

    # New binaries invalidate every source, otherwise only rescan what moved
    sources_to_scan = [
        s
        for s in GAMEDATA_SOURCES
        if binaries_stale or changed[s["name"]] or not s["signatures"].exists()
    ]

    if binaries_stale:
        print("Downloading CS2 binaries...")
        download_depots(workspace)
    else:
        print("Reusing existing binaries (only gamedata changed).")

    ready = []
    for source in sources_to_scan:
        if changed[source["name"]] or not source["signatures"].exists():
            if not prepare_signatures_jsonc(source):
                print(f"[{source['name']}] Conversion failed, skipping this source.")
                continue
        else:
            print(f"[{source['name']}] Reusing existing {source['signatures'].name}.")
        ready.append(source)

    if not ready:
        print("No gamedata sources ready to scan.")
        return

    vfunc_results = {}
    scan_results = {s["name"]: {} for s in ready}

    for os_name in ["windows", "linux"]:
        print(f"\nScanning [{os_name}] ...")
        s2binlib.initialize(f"./{workspace}/binaries/game", "csgo", os_name)
        vfunc_results[os_name] = dump_vfunc_counts(os_name, workspace, sig)
        for source in ready:
            scan_results[source["name"]][os_name] = pattern_scan(os_name, sig, source)

    if not SKIP_VFUNC and any(vfunc_results.values()):
        notify_vfunc_results(vfunc_results, sig)

    scan_results = {name: r for name, r in scan_results.items() if any(r.values())}
    if scan_results:
        notify_pattern_scan_results(scan_results, sig)

    latest = OUTPUT_DIR / "latest"
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(OUTPUT_DIR / sig, latest)

    print(f"\nDone - results in output/{sig}/ and output/latest/")


if __name__ == "__main__":
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
    print(f"Skip vfunc    : {SKIP_VFUNC}")
    print("Gamedata      :")
    for source in GAMEDATA_SOURCES:
        print(f"  • {source['name']}: {source['local'] or source['url']}")
    if not GAMEDATA_SOURCES:
        print("  • none")

    from discord_notifier import WEBHOOK_CONFIGS

    known_sources = {s["name"].lower() for s in GAMEDATA_SOURCES}
    print("Webhooks      :")
    for webhook in WEBHOOK_CONFIGS:
        subscribed = webhook["gamedata_sources"]
        print(
            f"  • {webhook['name']}: {', '.join(subscribed) if subscribed else 'all sources'}"
        )
        unknown = [n for n in subscribed if n.lower() not in known_sources]
        if unknown:
            print(f"    Warning: no such gamedata source: {', '.join(unknown)}")
    if not WEBHOOK_CONFIGS:
        print("  • none")
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
