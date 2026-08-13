import os
import re
import json
import time
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

MAX_FIELD_CHARS = 1024
MAX_FIELDS_PER_EMBED = 25
MAX_EMBED_CHARS = 5800  # headroom under Discord's 6000 per-message budget
MAX_EMBEDS_PER_MESSAGE = 10
MAX_MESSAGE_CHARS = 6000
MAX_FILES_PER_MESSAGE = 10

POST_RETRIES = 3
MAX_RETRY_WAIT = 60  # seconds, so a throttled webhook can't stall the poll loop

DEFAULT_COLOR = 5814783
COLOR_OK = 3066993
COLOR_WARN = 16776960
COLOR_FAIL = 15158332


def _name_list(raw):
    return [n.strip() for n in raw.split(",") if n.strip()]


def load_webhook_configs():
    """
    Load webhook configurations from environment variables.

    Multi-webhook format:
        DISCORD_WEBHOOKS=name1,name2
        NAME1_WEBHOOK_URL=https://...
        NAME1_NOTIFY_VFUNC=1
        NAME1_NOTIFY_PATTERNS=1
        NAME1_ATTACH_JSON=1
        NAME1_GAMEDATA_SOURCES=kz,misc   (unset = every source)

    Legacy single-webhook fallback (used when DISCORD_WEBHOOKS is not set):
        DISCORD_WEBHOOK=https://...
        NOTIFY_VFUNC=1  NOTIFY_PATTERNS=1  WEBHOOK_ATTACH_JSON=1
    """
    configs = []

    webhook_names = os.getenv("DISCORD_WEBHOOKS", "").strip()

    if webhook_names:
        for name in webhook_names.split(","):
            name = name.strip()
            if not name:
                continue
            prefix = name.upper()
            url = os.getenv(f"{prefix}_WEBHOOK_URL", "")
            if not url:
                print(
                    f"Warning: {prefix}_WEBHOOK_URL not set, skipping webhook '{name}'"
                )
                continue
            configs.append(
                {
                    "name": name,
                    "url": url,
                    "notify_vfunc": os.getenv(f"{prefix}_NOTIFY_VFUNC", "1") == "1",
                    "notify_patterns": os.getenv(f"{prefix}_NOTIFY_PATTERNS", "1")
                    == "1",
                    "attach_json": os.getenv(f"{prefix}_ATTACH_JSON", "1") == "1",
                    "patterns_only_on_failure": int(
                        os.getenv(f"{prefix}_PATTERNS_ONLY_ON_FAILURE", "0")
                    ),
                    "gamedata_sources": _name_list(
                        os.getenv(f"{prefix}_GAMEDATA_SOURCES", "")
                    ),
                }
            )
    else:
        url = os.getenv("DISCORD_WEBHOOK", "")
        if url:
            configs.append(
                {
                    "name": "default",
                    "url": url,
                    "notify_vfunc": os.getenv("NOTIFY_VFUNC", "1") == "1",
                    "notify_patterns": os.getenv("NOTIFY_PATTERNS", "1") == "1",
                    "attach_json": os.getenv("WEBHOOK_ATTACH_JSON", "1") == "1",
                    "patterns_only_on_failure": int(
                        os.getenv("PATTERNS_ONLY_ON_FAILURE", "0")
                    ),
                    "gamedata_sources": _name_list(
                        os.getenv("WEBHOOK_GAMEDATA_SOURCES", "")
                    ),
                }
            )

    return configs


WEBHOOK_CONFIGS = load_webhook_configs()


def build_line_fields(lines, base_name="Results"):
    """Pack lines into embed fields, splitting once a field would exceed 1024 chars."""
    fields = []

    def flush(buffer):
        fields.append(
            {
                "name": base_name if not fields else f"\u200B",
                "value": "\n".join(buffer)[:MAX_FIELD_CHARS],
                "inline": False,
            }
        )

    current = []
    length = 0
    for line in lines:
        line_length = len(line) + 1
        if current and length + line_length > MAX_FIELD_CHARS:
            flush(current)
            current = [line]
            length = line_length
        else:
            current.append(line)
            length += line_length

    if current:
        flush(current)

    return fields


def _embed(title, fields, color):
    embed = {
        "title": title,
        "color": DEFAULT_COLOR if color is None else color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed["fields"] = fields
    return embed


def _embed_chars(embed):
    total = len(embed.get("title", ""))
    for field in embed.get("fields", []):
        total += len(field["name"]) + len(field["value"])
    return total


def build_embeds(title, fields, color=None):
    """Build one embed holding every field, spilling into "(cont.)" embeds only when the field or character limits force it."""
    embeds = []
    current = []
    length = len(title)

    for field in fields:
        field_chars = len(field["name"]) + len(field["value"])
        if current and (
            len(current) >= MAX_FIELDS_PER_EMBED
            or length + field_chars > MAX_EMBED_CHARS
        ):
            embeds.append(
                _embed(title if not embeds else f"{title} (cont.)", current, color)
            )
            current = []
            length = len(title) + 8
        current.append(field)
        length += field_chars

    if current or not embeds:
        embeds.append(
            _embed(title if not embeds else f"{title} (cont.)", current, color)
        )

    return embeds


def _retry_after(response):
    """Seconds Discord wants us to wait, from the header or the JSON body."""
    raw = response.headers.get("Retry-After")
    if raw is None:
        try:
            raw = response.json().get("retry_after")
        except Exception:
            raw = None
    if raw is None:
        return 5.0
    try:
        return min(max(float(raw), 1.0), MAX_RETRY_WAIT)
    except (TypeError, ValueError):
        return 5.0


def _post(webhook_url, payload, files=None):
    titles = ", ".join(e.get("title", "embed") for e in payload.get("embeds", []))

    for attempt in range(1, POST_RETRIES + 1):
        try:
            if files:
                files_to_upload = {}
                for i, file_info in enumerate(files):
                    files_to_upload[f"file{i}"] = (
                        file_info["filename"],
                        file_info["content"],
                        "application/json",
                    )

                response = requests.post(
                    webhook_url,
                    data={"payload_json": json.dumps(payload)},
                    files=files_to_upload,
                )
            else:
                response = requests.post(webhook_url, json=payload)

            # Several sources means several messages per run, so throttling is expected
            if response.status_code == 429 and attempt < POST_RETRIES:
                wait = _retry_after(response)
                print(f"Discord rate limited, retrying in {wait:.1f}s: {titles}")
                time.sleep(wait)
                continue

            response.raise_for_status()
            print(f"Discord notification sent: {titles}")
            return
        except Exception as e:
            print(f"Failed to send Discord notification: {e}")
            return


def send_discord_embeds(webhook_url, embeds, files=None):
    """Send embeds, splitting into extra messages when Discord's per-message limits bite."""
    if not embeds:
        return

    files = list(files or [])
    if len(files) > MAX_FILES_PER_MESSAGE:
        print(
            f"Warning: {len(files)} attachments exceed Discord's limit, sending the first {MAX_FILES_PER_MESSAGE}"
        )
        files = files[:MAX_FILES_PER_MESSAGE]

    batches = []
    current = []
    chars = 0
    for embed in embeds:
        embed_chars = _embed_chars(embed)
        if current and (
            len(current) >= MAX_EMBEDS_PER_MESSAGE
            or chars + embed_chars > MAX_MESSAGE_CHARS
        ):
            batches.append(current)
            current = []
            chars = 0
        current.append(embed)
        chars += embed_chars

    if current:
        batches.append(current)

    for i, batch in enumerate(batches):
        is_last = i == len(batches) - 1
        _post(webhook_url, {"embeds": batch}, files if (files and is_last) else None)


def send_discord_webhook(webhook_url, title, fields=None, color=None, files=None):
    send_discord_embeds(webhook_url, build_embeds(title, fields or [], color), files)


def _status_color(failed, checks):
    if failed == 0:
        return COLOR_OK
    return COLOR_WARN if failed < checks / 2 else COLOR_FAIL


def _file_slug(name):
    """Must match main._slugify so attachments and on-disk results share a name."""
    return re.sub(r"[^a-z0-9._-]", "_", name.lower())


def notify_vfunc_results(vfunc_results, signature):
    webhooks = [w for w in WEBHOOK_CONFIGS if w["notify_vfunc"]]
    if not webhooks:
        return

    windows_results = {r["class_name"]: r for r in vfunc_results.get("windows", [])}
    linux_results = {r["class_name"]: r for r in vfunc_results.get("linux", [])}

    all_classes = set(windows_results.keys()) | set(linux_results.keys())

    total_classes = len(all_classes)
    windows_success = sum(
        1 for r in windows_results.values() if r.get("vfunc_count", 0) > 0
    )
    linux_success = sum(
        1 for r in linux_results.values() if r.get("vfunc_count", 0) > 0
    )

    fields = [
        {"name": "Build Signature", "value": signature, "inline": False},
        {"name": "Total VTables", "value": str(total_classes), "inline": True},
        {"name": "Windows Success", "value": str(windows_success), "inline": True},
        {"name": "Linux Success", "value": str(linux_success), "inline": True},
    ]

    binary_groups = {}
    for class_name in all_classes:
        win_result = windows_results.get(class_name)
        lin_result = linux_results.get(class_name)

        result = win_result or lin_result
        binary = result.get("binary", "Unknown") if result else "Unknown"

        if binary not in binary_groups:
            binary_groups[binary] = []

        win_count = win_result["vfunc_count"] if win_result else 0
        lin_count = lin_result["vfunc_count"] if lin_result else 0

        binary_groups[binary].append(
            f"`{class_name}` → Windows `[{win_count}]`, Linux `[{lin_count}]`"
        )

    for binary in sorted(binary_groups.keys()):
        fields.extend(build_line_fields(sorted(binary_groups[binary]), binary))

    windows_failed = total_classes - windows_success
    linux_failed = total_classes - linux_success
    color = _status_color(windows_failed + linux_failed, total_classes * 2)

    files_to_upload = [
        {
            "filename": f"vfunc_counts_windows_{signature}.json",
            "content": json.dumps(vfunc_results.get("windows", []), indent=4),
        },
        {
            "filename": f"vfunc_counts_linux_{signature}.json",
            "content": json.dumps(vfunc_results.get("linux", []), indent=4),
        },
    ]

    embeds = build_embeds("VFunc Offsets - Windows & Linux", fields, color)
    for webhook in webhooks:
        send_discord_embeds(
            webhook["url"],
            embeds,
            files_to_upload if webhook["attach_json"] else None,
        )


def _entry_result(entry):
    """(count, ok, present) for one scan entry. A missing entry is not a failure."""
    if entry is None:
        return (0, False, False)
    count = entry.get("count", 0)
    ok = count == 1 or (count > 1 and entry.get("allow_multi_match", False))
    return (count, ok, True)


def _circle(result):
    count, ok, _ = result
    if ok:
        return "🟢"
    return "🔴" if count == 0 else "🟡"


def _merge_sources(scan_results_by_source):
    """
    Collapse every gamedata source into one result table.

    Sources that agree on a signature share a single row.
    A signature whose results differ between sources gets one row per distinct result,
    tagged with the sources that produced it.
    """
    variants = {}
    per_source = []

    for source_name in sorted(scan_results_by_source):
        results = scan_results_by_source[source_name]
        windows = {r["signature"]: r for r in results.get("windows", [])}
        linux = {r["signature"]: r for r in results.get("linux", [])}

        win_ok = sum(1 for r in windows.values() if _entry_result(r)[1])
        lin_ok = sum(1 for r in linux.values() if _entry_result(r)[1])
        per_source.append(
            {
                "name": source_name,
                "total": len(set(windows) | set(linux)),
                "windows": (win_ok, len(windows) - win_ok),
                "linux": (lin_ok, len(linux) - lin_ok),
            }
        )

        for sig_name in set(windows) | set(linux):
            key = (
                _entry_result(windows.get(sig_name)),
                _entry_result(linux.get(sig_name)),
            )
            variants.setdefault(sig_name, {}).setdefault(key, []).append(source_name)

    rows = []
    for sig_name in sorted(variants):
        by_result = variants[sig_name]
        tagged = len(by_result) > 1
        for (win, lin), owners in sorted(
            by_result.items(), key=lambda kv: sorted(kv[1])
        ):
            label = f"`{sig_name}`"
            if tagged:
                label += f" ({', '.join(sorted(owners))})"
            rows.append(
                {
                    "line": f"{label} → Windows `[{win[0]}]` {_circle(win)}, Linux `[{lin[0]}]` {_circle(lin)}",
                    "windows": win,
                    "linux": lin,
                }
            )

    return rows, per_source


def _build_pattern_payload(scan_results_by_source, signature):
    """Merge one webhook's sources into the fields, lines and files it will send."""
    rows, per_source = _merge_sources(scan_results_by_source)
    if not rows:
        return None

    windows_success = sum(1 for r in rows if r["windows"][1])
    linux_success = sum(1 for r in rows if r["linux"][1])
    windows_failed = sum(1 for r in rows if r["windows"][2] and not r["windows"][1])
    linux_failed = sum(1 for r in rows if r["linux"][2] and not r["linux"][1])

    total_failed = windows_failed + linux_failed
    total_checks = sum(1 for r in rows if r["windows"][2]) + sum(
        1 for r in rows if r["linux"][2]
    )
    color = _status_color(total_failed, total_checks)

    base_fields = [
        {"name": "Build Signature", "value": signature, "inline": False},
        {"name": "Total Signatures", "value": str(len(rows)), "inline": True},
        {
            "name": "Windows Success/Failed",
            "value": f"{windows_success}/{windows_failed}",
            "inline": True,
        },
        {
            "name": "Linux Success/Failed",
            "value": f"{linux_success}/{linux_failed}",
            "inline": True,
        },
    ]

    if len(per_source) > 1:
        base_fields.append(
            {
                "name": "Gamedata Sources",
                "value": "\n".join(
                    f"`{s['name']}` → {s['total']} sigs, Windows {s['windows'][0]}/{s['windows'][1]}, "
                    f"Linux {s['linux'][0]}/{s['linux'][1]}"
                    for s in per_source
                )[:MAX_FIELD_CHARS],
                "inline": False,
            }
        )

    all_lines = [r["line"] for r in rows]
    failing_lines = [
        r["line"]
        for r in rows
        if (r["windows"][2] and not r["windows"][1])
        or (r["linux"][2] and not r["linux"][1])
    ]

    files_to_upload = []
    for source_name in sorted(scan_results_by_source):
        results = scan_results_by_source[source_name]
        slug = _file_slug(source_name)
        for os_name in ("windows", "linux"):
            files_to_upload.append(
                {
                    "filename": f"signatures_{slug}_{os_name}_{signature}.json",
                    "content": json.dumps(results.get(os_name, []), indent=4),
                }
            )

    return {
        "base_fields": base_fields,
        "all_lines": all_lines,
        "failing_lines": failing_lines,
        "total_failed": total_failed,
        "color": color,
        "files": files_to_upload,
    }


def notify_pattern_scan_results(scan_results_by_source, signature):
    """
    scan_results_by_source: {source_name: {'windows': [...], 'linux': [...]}}

    Each webhook sees only the sources it subscribes to, merged into one embed with rows deduplicated across those sources.
    """
    webhooks = [w for w in WEBHOOK_CONFIGS if w["notify_patterns"]]
    if not webhooks:
        return

    payloads = {}

    for webhook in webhooks:
        wanted = {n.lower() for n in webhook.get("gamedata_sources", [])}
        subset = {
            name: results
            for name, results in scan_results_by_source.items()
            if not wanted or name.lower() in wanted
        }
        if not subset:
            continue

        key = tuple(sorted(subset))
        if key not in payloads:
            payloads[key] = _build_pattern_payload(subset, signature)
        payload = payloads[key]
        if payload is None:
            continue

        mode = webhook.get("patterns_only_on_failure", 0)
        if mode == 1:
            if payload["total_failed"] == 0:
                continue
            lines = payload["failing_lines"]
        elif mode == 2:
            lines = [] if payload["total_failed"] == 0 else payload["failing_lines"]
        else:
            lines = payload["all_lines"]

        fields = payload["base_fields"] + build_line_fields(lines)
        send_discord_embeds(
            webhook["url"],
            build_embeds(
                "Pattern Scan Results - Windows & Linux", fields, payload["color"]
            ),
            payload["files"] if webhook["attach_json"] else None,
        )
