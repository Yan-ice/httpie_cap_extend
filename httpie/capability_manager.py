import json
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .cli.dicts import HTTPHeadersDict

CAPABILITY_HEADER = 'X-Capability'
CAPABILITY_REQUIRED_SID_HEADER = 'X-Capability-Required-Sid'
DEFAULT_SYSTEM_CAP_DIR = '~/.agent_capability'
DEFAULT_CAPCLI_PATH = 'cap-cli'


def get_system_capability_dir() -> Path:
    return Path(
        os.environ.get('CAP_AGENT_SYSTEM_CAP_DIR', DEFAULT_SYSTEM_CAP_DIR)
    ).expanduser().resolve()


def resolve_required_sid(headers: HTTPHeadersDict) -> str:
    """
    Resolve required capability sid from:
    1) request hint header `X-Capability-Required-Sid`
    2) env `CAP_REQUIRED_SID` / `HTTP_CAP_REQUIRED_SID`
    """
    sid = headers.get(CAPABILITY_REQUIRED_SID_HEADER)
    if sid:
        sid_text = str(sid).strip()
        if sid_text:
            return sid_text

    for env_key in ('CAP_REQUIRED_SID', 'HTTP_CAP_REQUIRED_SID'):
        sid_text = os.environ.get(env_key, '').strip()
        if sid_text:
            return sid_text
    return ''


def load_capability_by_sid(required_sid: str, cap_dir: Path) -> dict[str, Any] | None:
    if not required_sid or not cap_dir.is_dir():
        return None
    for cap_path in sorted(cap_dir.rglob('*.cap')):
        try:
            data = json.loads(cap_path.read_text(encoding='utf-8'))
            if str(data.get('sid', '')).strip() == required_sid:
                return data
        except Exception:
            continue
    return None


def serialize_capability_header_from_sid(required_sid: str) -> str | None:
    cap_payload = load_capability_by_sid(required_sid, get_system_capability_dir())
    if cap_payload is None:
        return None
    return json.dumps(cap_payload, ensure_ascii=False, separators=(',', ':'))


def auto_attach_capability_header(headers: HTTPHeadersDict) -> None:
    """
    Attach `X-Capability` header by scanning capability directory for a `.cap`
    whose sid matches required sid.
    """
    if headers.get(CAPABILITY_HEADER):
        return

    required_sid = resolve_required_sid(headers)
    if not required_sid:
        return

    cap_payload = load_capability_by_sid(required_sid, get_system_capability_dir())
    if cap_payload is None:
        return

    headers[CAPABILITY_HEADER] = json.dumps(cap_payload, ensure_ascii=False, separators=(',', ':'))
    if CAPABILITY_REQUIRED_SID_HEADER in headers:
        headers.popone(CAPABILITY_REQUIRED_SID_HEADER)


def is_retryable_request_body(body: Any) -> bool:
    return body is None or isinstance(body, (bytes, str))


def serialize_capability_param_text(
    params: Mapping[str, Any],
    ordered_keys: Sequence[str] | None = None,
) -> str:
    """
    Serialize params for cap-cli verify/request:
    - each k=v pair is separated by ';'
    - list values are separated by ','
    """
    keys = list(ordered_keys) if ordered_keys is not None else list(params.keys())
    items: list[str] = []
    for key in keys:
        if key == 'capability':
            continue
        items.append(f'{key}={_encode_capability_param_value(params.get(key))}')
    return ';'.join(items)


def _encode_capability_param_value(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ','.join(_encode_capability_list_item(v) for v in value)
    try:
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    except Exception:
        return ''


def _encode_capability_list_item(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float, str)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    except Exception:
        return ''


def capcli_request(
    cap_file: str,
    key_file: str,
    params: Mapping[str, Any],
    output_file: str,
    ordered_keys: Sequence[str] | None = None,
    capcli_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    param_text = serialize_capability_param_text(params, ordered_keys=ordered_keys)
    cli = capcli_path or os.environ.get('CAP_AGENT_CAPCLI_PATH', DEFAULT_CAPCLI_PATH)
    cmd = [cli, 'request', '-f', cap_file, '-k', key_file, '-p', param_text, '-o', output_file]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def capcli_verify(
    request_file: str,
    root_file: str,
    params: Mapping[str, Any],
    additional_params: Mapping[str, Any] | None = None,
    ordered_keys: Sequence[str] | None = None,
    capcli_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    param_text = serialize_capability_param_text(params, ordered_keys=ordered_keys)
    cli = capcli_path or os.environ.get('CAP_AGENT_CAPCLI_PATH', DEFAULT_CAPCLI_PATH)
    cmd = [cli, 'verify', '-f', request_file, '-r', root_file, '-p', param_text]
    if additional_params is not None:
        additional_text = serialize_capability_param_text(additional_params)
        cmd.extend(['-a', additional_text])
    return subprocess.run(cmd, capture_output=True, text=True, check=False)
