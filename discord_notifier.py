import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def load_webhook_configs():
    """
    Load webhook configurations from environment variables.

    Multi-webhook format:
        DISCORD_WEBHOOKS=name1,name2
        NAME1_WEBHOOK_URL=https://...
        NAME1_NOTIFY_VFUNC=1
        NAME1_NOTIFY_PATTERNS=1
        NAME1_ATTACH_JSON=1

    Legacy single-webhook fallback (used when DISCORD_WEBHOOKS is not set):
        DISCORD_WEBHOOK=https://...
        NOTIFY_VFUNC=1  NOTIFY_PATTERNS=1  WEBHOOK_ATTACH_JSON=1
    """
    configs = []

    webhook_names = os.getenv('DISCORD_WEBHOOKS', '').strip()

    if webhook_names:
        for name in webhook_names.split(','):
            name = name.strip()
            if not name:
                continue
            prefix = name.upper()
            url = os.getenv(f'{prefix}_WEBHOOK_URL', '')
            if not url:
                print(f"Warning: {prefix}_WEBHOOK_URL not set, skipping webhook '{name}'")
                continue
            configs.append({
                'name': name,
                'url': url,
                'notify_vfunc': os.getenv(f'{prefix}_NOTIFY_VFUNC', '1') == '1',
                'notify_patterns': os.getenv(f'{prefix}_NOTIFY_PATTERNS', '1') == '1',
                'attach_json': os.getenv(f'{prefix}_ATTACH_JSON', '1') == '1',
                'patterns_only_on_failure': os.getenv(f'{prefix}_PATTERNS_ONLY_ON_FAILURE', '0') == '1',
            })
    else:
        url = os.getenv('DISCORD_WEBHOOK', '')
        if url:
            configs.append({
                'name': 'default',
                'url': url,
                'notify_vfunc': os.getenv('NOTIFY_VFUNC', '1') == '1',
                'notify_patterns': os.getenv('NOTIFY_PATTERNS', '1') == '1',
                'attach_json': os.getenv('WEBHOOK_ATTACH_JSON', '1') == '1',
                'patterns_only_on_failure': os.getenv('PATTERNS_ONLY_ON_FAILURE', '0') == '1',
            })

    return configs


WEBHOOK_CONFIGS = load_webhook_configs()


def send_discord_webhook(webhook_url, title, description, fields=None, color=None, files=None):
    if color is None:
        color = 5814783

    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {
            "text": "GameData Validator"
        }
    }

    if fields:
        embed["fields"] = fields

    payload = {
        "embeds": [embed]
    }

    try:
        if files:
            import json as json_lib
            files_to_upload = {}
            for i, file_info in enumerate(files):
                files_to_upload[f'file{i}'] = (
                    file_info['filename'],
                    file_info['content'],
                    'application/json'
                )

            response = requests.post(
                webhook_url,
                data={'payload_json': json_lib.dumps(payload)},
                files=files_to_upload
            )
        else:
            response = requests.post(webhook_url, json=payload)

        response.raise_for_status()
        print(f"Discord notification sent: {title}")
    except Exception as e:
        print(f"Failed to send Discord notification: {e}")


def notify_vfunc_results(vfunc_results, signature):
    webhooks = [w for w in WEBHOOK_CONFIGS if w['notify_vfunc']]
    if not webhooks:
        return

    windows_results = {r['class_name']: r for r in vfunc_results.get('windows', [])}
    linux_results = {r['class_name']: r for r in vfunc_results.get('linux', [])}

    all_classes = set(windows_results.keys()) | set(linux_results.keys())

    total_classes = len(all_classes)
    windows_success = sum(1 for r in windows_results.values() if r.get('vfunc_count', 0) > 0)
    linux_success = sum(1 for r in linux_results.values() if r.get('vfunc_count', 0) > 0)

    fields = [
        {
            "name": "Build Signature",
            "value": signature,
            "inline": False
        },
        {
            "name": "Total VTables",
            "value": str(total_classes),
            "inline": True
        },
        {
            "name": "Windows Success",
            "value": str(windows_success),
            "inline": True
        },
        {
            "name": "Linux Success",
            "value": str(linux_success),
            "inline": True
        }
    ]

    binary_groups = {}
    for class_name in all_classes:
        win_result = windows_results.get(class_name)
        lin_result = linux_results.get(class_name)

        result = win_result or lin_result
        binary = result.get('binary', 'Unknown') if result else 'Unknown'

        if binary not in binary_groups:
            binary_groups[binary] = []

        win_count = win_result['vfunc_count'] if win_result else 0
        lin_count = lin_result['vfunc_count'] if lin_result else 0

        binary_groups[binary].append(
            f"`{class_name}` → Windows `[{win_count}]`, Linux `[{lin_count}]`"
        )

    for binary in sorted(binary_groups.keys()):
        vtables = binary_groups[binary]

        max_field_length = 1024
        current_field = []
        current_length = 0
        field_index = 0

        for vtable_line in vtables:
            line_length = len(vtable_line) + 1
            if current_length + line_length > max_field_length:
                field_name = binary if field_index == 0 else f"{binary} (cont.)"
                fields.append({
                    "name": field_name,
                    "value": "\n".join(current_field),
                    "inline": False
                })
                current_field = [vtable_line]
                current_length = line_length
                field_index += 1
            else:
                current_field.append(vtable_line)
                current_length += line_length

        if current_field:
            field_name = binary if field_index == 0 else f"{binary} (cont.)"
            fields.append({
                "name": field_name,
                "value": "\n".join(current_field),
                "inline": False
            })

    windows_failed = total_classes - windows_success
    linux_failed = total_classes - linux_success
    total_failed = windows_failed + linux_failed
    total_checks = total_classes * 2

    if total_failed == 0:
        color = 3066993
    elif total_failed < total_checks / 2:
        color = 16776960
    else:
        color = 15158332

    import json as json_lib
    files_to_upload = [
        {
            'filename': f'vfunc_counts_windows_{signature}.json',
            'content': json_lib.dumps(vfunc_results.get('windows', []), indent=4)
        },
        {
            'filename': f'vfunc_counts_linux_{signature}.json',
            'content': json_lib.dumps(vfunc_results.get('linux', []), indent=4)
        }
    ]

    for webhook in webhooks:
        send_discord_webhook(
            webhook_url=webhook['url'],
            title="VFunc Offsets - Windows & Linux",
            description=f"Virtual function offset analysis completed for both platforms",
            fields=fields,
            color=color,
            files=files_to_upload if webhook['attach_json'] else None
        )


def notify_pattern_scan_results(scan_results, signature):
    webhooks = [w for w in WEBHOOK_CONFIGS if w['notify_patterns']]
    if not webhooks:
        return

    def get_circle(count, allow_multi_match=False):
        if count == 0:
            return "🔴"
        elif count == 1:
            return "🟢"
        elif allow_multi_match:
            return "🟢"
        else:
            return "🟡"

    windows_results = {r['signature']: r for r in scan_results.get('windows', [])}
    linux_results = {r['signature']: r for r in scan_results.get('linux', [])}

    all_signatures = set(windows_results.keys()) | set(linux_results.keys())

    def is_success(r):
        count = r.get('count', 0)
        return count == 1 or (count > 1 and r.get('allow_multi_match', False))

    total_signatures = len(all_signatures)
    windows_success = sum(1 for r in windows_results.values() if is_success(r))
    linux_success = sum(1 for r in linux_results.values() if is_success(r))
    windows_failed = len(windows_results) - windows_success
    linux_failed = len(linux_results) - linux_success

    fields = [
        {
            "name": "Build Signature",
            "value": signature,
            "inline": False
        },
        {
            "name": "Total Signatures",
            "value": str(total_signatures),
            "inline": True
        },
        {
            "name": "Windows Success/Failed",
            "value": f"{windows_success}/{windows_failed}",
            "inline": True
        },
        {
            "name": "Linux Success/Failed",
            "value": f"{linux_success}/{linux_failed}",
            "inline": True
        }
    ]

    all_lines = []
    failing_lines = []
    for sig_name in sorted(all_signatures):
        win_result = windows_results.get(sig_name)
        lin_result = linux_results.get(sig_name)

        win_count = win_result['count'] if win_result else 0
        lin_count = lin_result['count'] if lin_result else 0

        win_multi = win_result.get('allow_multi_match', False) if win_result else False
        lin_multi = lin_result.get('allow_multi_match', False) if lin_result else False

        win_circle = get_circle(win_count, win_multi)
        lin_circle = get_circle(lin_count, lin_multi)

        line = f"`{sig_name}` → Windows `[{win_count}]` {win_circle}, Linux `[{lin_count}]` {lin_circle}"
        all_lines.append(line)

        win_failed = not is_success(win_result) if win_result else False
        lin_failed = not is_success(lin_result) if lin_result else False
        if win_failed or lin_failed:
            failing_lines.append(line)

    def build_result_fields(lines, base_fields):
        result_fields = list(base_fields)
        max_field_length = 1024
        current_field = []
        current_length = 0

        for line in lines:
            line_length = len(line) + 1
            if current_length + line_length > max_field_length:
                result_fields.append({
                    "name": "Results" if len([f for f in result_fields if f['name'].startswith('Results')]) == 0 else "Results (cont.)",
                    "value": "\n".join(current_field),
                    "inline": False
                })
                current_field = [line]
                current_length = line_length
            else:
                current_field.append(line)
                current_length += line_length

        if current_field:
            result_fields.append({
                "name": "Results" if len([f for f in result_fields if f['name'].startswith('Results')]) == 0 else "Results (cont.)",
                "value": "\n".join(current_field),
                "inline": False
            })

        return result_fields

    total_failed = windows_failed + linux_failed
    total_checks = len(windows_results) + len(linux_results)

    if total_failed == 0:
        color = 3066993
    elif total_failed < total_checks / 2:
        color = 16776960
    else:
        color = 15158332

    import json as json_lib
    files_to_upload = [
        {
            'filename': f'signatures_windows_{signature}.json',
            'content': json_lib.dumps(scan_results.get('windows', []), indent=4)
        },
        {
            'filename': f'signatures_linux_{signature}.json',
            'content': json_lib.dumps(scan_results.get('linux', []), indent=4)
        }
    ]

    for webhook in webhooks:
        if webhook.get('patterns_only_on_failure'):
            if total_failed == 0:
                continue
            webhook_fields = build_result_fields(failing_lines, fields)
        else:
            webhook_fields = build_result_fields(all_lines, fields)

        send_discord_webhook(
            webhook_url=webhook['url'],
            title="Pattern Scan Results - Windows & Linux",
            description=f"Pattern scanning completed for both platforms",
            fields=webhook_fields,
            color=color,
            files=files_to_upload if webhook['attach_json'] else None
        )
