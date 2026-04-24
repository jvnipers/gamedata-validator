"""
steamchecker.py — Drop-in replacement using the public SteamCMD HTTP API.
No Steam login required. No gevent. No SteamClient.
"""

import time
import hashlib
import requests
from pathlib import Path

_CACHE_DIR = Path("cache")

_build_id = ""
_s = ""

_DEPOT_WIN   = "2347771"
_DEPOT_LINUX = "2347773"

_STEAMCMD_API = "https://api.steamcmd.net/v1/info/730"

_KZ_GAMEDATA_URL = (
    "https://raw.githubusercontent.com/KZGlobalTeam/cs2kz-metamod"
    "/master/gamedata/cs2kz-core.games.txt"
)


def _fetch_steam_info() -> dict:
    resp = requests.get(_STEAMCMD_API, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "success":
        raise RuntimeError(f"SteamCMD API returned non-success: {data.get('status')}")
    return data["data"]["730"]


def _get_file_hash(url: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    resp = requests.get(url, stream=True, timeout=30)
    resp.raise_for_status()
    for chunk in resp.iter_content(chunk_size=8192):
        if chunk:
            h.update(chunk)
    return h.hexdigest()


def GetKZGamedataHash() -> str:
    """SHA-256 of the live cs2kz-core.games.txt on GitHub."""
    return _get_file_hash(_KZ_GAMEDATA_URL)


def CheckGameUpdates(app_id: int) -> list | bool:
    """
    Check whether CS2 depots or the KZ gamedata have changed since the last run.
    Returns a list of changed item names, [] if nothing changed, or False on error.
    """
    global _build_id

    try:
        info = _fetch_steam_info()
    except Exception as e:
        print(f"SteamCMD API error: {e}")
        return False

    depots      = info["depots"]
    _build_id   = str(depots["branches"]["public"]["buildid"])
    gid_win     = str(depots[_DEPOT_WIN]["manifests"]["public"]["gid"])
    gid_linux   = str(depots[_DEPOT_LINUX]["manifests"]["public"]["gid"])

    try:
        kz_hash = GetKZGamedataHash()
    except Exception as e:
        print(f"Could not hash KZ gamedata: {e}")
        kz_hash = "unknown"

    update_signature = f"{_build_id}|{gid_win}|{gid_linux}|{kz_hash}"

    public_file = _CACHE_DIR / f"public{app_id}.txt"
    try:
        with open(public_file) as f:
            file_info = f.read()
    except FileNotFoundError:
        file_info = ""

    updated = []
    if gid_win   not in file_info:
        updated.append(_DEPOT_WIN)
    if gid_linux not in file_info:
        updated.append(_DEPOT_LINUX)
    if update_signature not in file_info:
        updated.append("cs2kz-gamedata")

    if updated:
        try:
            with open(public_file, "a") as f:
                f.write(f"\n{update_signature}")
        except Exception as e:
            print(f"Could not write {public_file}: {e}")
            return []

    return updated


def GetSignature() -> str:
    """Return a unique run identifier: <build_id>_<unix_timestamp>."""
    global _s
    if _s:
        return _s
    _s = f"{_build_id}_{int(time.time())}"
    return _s
