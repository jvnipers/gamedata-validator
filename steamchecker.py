"""
steamchecker.py - Queries Steam PICS directly via an anonymous SteamClient.
"""

import time
import hashlib
import requests
from pathlib import Path

from gevent import Timeout as _GeventTimeout

_PICS_RETRIES = 3
_PICS_RETRY_DELAY = 5  # seconds between attempts
_PICS_ATTEMPT_TIMEOUT = 60  # seconds before giving up on a hung login

from steam.client import SteamClient
from steam.enums import EResult

_CACHE_DIR = Path("cache")

_build_id = ""

_DEPOT_WIN   = "2347771"
_DEPOT_LINUX = "2347773"

_KZ_GAMEDATA_URL = (
    "https://raw.githubusercontent.com/KZGlobalTeam/cs2kz-metamod"
    "/master/gamedata/cs2kz-core.games.txt"
)


def _fetch_steam_info(app_id: int) -> dict:
    last_exc: BaseException | None = None
    for attempt in range(1, _PICS_RETRIES + 1):
        client = SteamClient()
        try:
            with _GeventTimeout(_PICS_ATTEMPT_TIMEOUT, RuntimeError(f"Steam PICS timed out after {_PICS_ATTEMPT_TIMEOUT}s")):
                result = client.anonymous_login()
                if result != EResult.OK:
                    raise RuntimeError(f"Anonymous Steam login failed: {result!r}")

                info = client.get_product_info(apps=[app_id], timeout=30)
                if not info or app_id not in info.get("apps", {}):
                    raise RuntimeError(f"PICS returned no info for app {app_id}")
                return info["apps"][app_id]
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                raise
            last_exc = e
            print(f"Steam PICS attempt {attempt}/{_PICS_RETRIES} failed: {e}")
            try:
                client.logout()
            except BaseException:
                pass
            if attempt < _PICS_RETRIES:
                time.sleep(_PICS_RETRY_DELAY)
    raise RuntimeError(f"Steam PICS failed after {_PICS_RETRIES} attempts") from (last_exc if isinstance(last_exc, Exception) else Exception(str(last_exc)))


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
        app = _fetch_steam_info(app_id)
    except Exception as e:
        print(f"Steam PICS error: {e}")
        return False

    depots      = app["depots"]
    _build_id   = str(depots["branches"]["public"]["buildid"])
    gid_win     = str(depots[_DEPOT_WIN]["manifests"]["public"]["gid"])
    gid_linux   = str(depots[_DEPOT_LINUX]["manifests"]["public"]["gid"])

    try:
        kz_hash = GetKZGamedataHash()
        kz_hash_ok = True
    except Exception as e:
        print(f"Could not hash KZ gamedata: {e}")
        kz_hash = "unknown"
        kz_hash_ok = False

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
    if kz_hash_ok and update_signature not in file_info:
        updated.append("cs2kz-gamedata")

    if updated:
        try:
            with open(public_file, "a") as f:
                f.write(f"\n{update_signature}")
        except Exception as e:
            print(f"Could not write {public_file}: {e}")
            return []

    return updated


def GetBuildId() -> str:
    """Return the current CS2 build ID (set after CheckGameUpdates)."""
    return _build_id


def GetSignature() -> str:
    """Return a unique run identifier: <build_id>_<unix_timestamp>."""
    return f"{_build_id}_{int(time.time())}"
