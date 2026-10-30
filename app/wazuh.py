import json
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from .schemas import EventIn


_EVENT_ID_MAP = {
    "1": "process_creation",
    "10": "lsass_access_signal",
    "4625": "failed_login",
    "4688": "process_creation",
    "4698": "scheduled_task_created",
    "4720": "account_created",
    "7045": "service_installed",
}
_CLOUD_EVENT_MAP = {
    "ConsoleLogin": "cloud_console_login",
    "AddUserToGroup": "cloud_role_assigned",
    "AttachRolePolicy": "cloud_role_assigned",
    "AttachUserPolicy": "cloud_role_assigned",
    "CreateRole": "cloud_role_assigned",
    "PutRolePolicy": "cloud_role_assigned",
    "PutUserPolicy": "cloud_role_assigned",
}


def _nested(value: Any, *path: str) -> Any:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _object_at(value: Any, *path: str) -> dict[str, Any]:
    result = _nested(value, *path)
    if result is None:
        return {}
    if not isinstance(result, dict):
        raise ValueError(f"Wazuh alert field '{'.'.join(path)}' must be an object")
    return result


def _first(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return default


def _text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True)
    return str(value) if value is not None else ""


def _event_type(alert: dict[str, Any], data: dict[str, Any]) -> str:
    explicit = _first(
        data.get("event_type"),
        _nested(data, "event", "type"),
        _nested(data, "win", "eventdata", "eventType"),
    )
    if explicit:
        return _text(explicit).strip().lower()

    win_event_id = _first(
        _nested(data, "win", "system", "eventID"),
        _nested(data, "windows", "event_id"),
        default=None,
    )
    if win_event_id is not None and str(win_event_id) in _EVENT_ID_MAP:
        event_type = _EVENT_ID_MAP[str(win_event_id)]
        if event_type == "lsass_access_signal":
            target = _text(_first(
                _nested(data, "win", "eventdata", "targetImage"),
                _nested(data, "win", "eventdata", "target_image"),
            )).lower()
            return event_type if "lsass.exe" in target else "process_access"
        return event_type

    event_name = _first(
        _nested(data, "aws", "eventName"),
        data.get("eventName"),
    )
    if event_name in _CLOUD_EVENT_MAP:
        return _CLOUD_EVENT_MAP[event_name]

    groups = alert.get("rule", {}).get("groups", [])
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, list):
        raise ValueError("Wazuh alert field 'rule.groups' must be a list or string")
    groups_text = " ".join(_text(group).lower() for group in groups)
    description = _text(alert.get("rule", {}).get("description", "")).lower()
    full_log = _text(_first(alert.get("full_log"), data.get("message"))).lower()
    search_text = " ".join((groups_text, description, full_log))
    if any(term in search_text for term in ("sshd", "ssh")) and any(
        term in search_text
        for term in ("failed", "failure", "invalid user", "authentication error")
    ):
        return "ssh_failed_login"
    if "sudo" in groups_text and any(
        term in search_text for term in ("command", "user", "session")
    ):
        return "sudo_command"
    if "authentication_failed" in groups_text or "invalid_login" in groups_text:
        return "failed_login"

    if win_event_id is not None:
        return f"windows_event_{win_event_id}"
    if event_name:
        return "cloud_event"
    rule_id = _text(_nested(alert, "rule", "id"))
    return f"wazuh_alert_{rule_id}" if rule_id else "wazuh_alert"


def normalize_wazuh_alert(alert: dict[str, Any]) -> EventIn:
    if not isinstance(alert, dict):
        raise ValueError("Wazuh alert must be a JSON object")

    data = alert.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("Wazuh alert 'data' field must be a JSON object")
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    if not isinstance(rule, dict) or not isinstance(agent, dict):
        raise ValueError("Wazuh alert 'rule' and 'agent' fields must be JSON objects")

    event_type = _event_type(alert, data)
    win_event = _object_at(data, "win", "eventdata")
    aws_identity = _object_at(data, "aws", "userIdentity")

    username = _first(
        data.get("dstuser"),
        data.get("srcuser"),
        _nested(data, "user", "name"),
        data.get("user"),
        win_event.get("targetUserName"),
        win_event.get("newTargetUserName"),
        win_event.get("subjectUserName"),
        win_event.get("user"),
        _nested(data, "audit", "auid"),
        aws_identity.get("userName"),
        _nested(aws_identity, "sessionContext", "sessionIssuer", "userName"),
        default="unknown",
    )
    source_ip = _first(
        data.get("srcip"),
        data.get("source_ip"),
        _nested(data, "source", "ip"),
        win_event.get("ipAddress"),
        _nested(data, "aws", "sourceIPAddress"),
        default="unknown",
    )
    process_name = _first(
        _nested(data, "process", "name"),
        win_event.get("image"),
        win_event.get("newProcessName"),
        data.get("process_name"),
        default="",
    )
    command_line = _first(
        _nested(data, "process", "command_line"),
        win_event.get("commandLine"),
        win_event.get("command_line"),
        data.get("command"),
        data.get("command_line"),
        default="",
    )

    rule_id = _text(rule.get("id", ""))
    rule_description = _text(rule.get("description", ""))
    agent_name = _text(agent.get("name", ""))
    location = _text(alert.get("location", ""))
    message_parts = [
        f"Wazuh rule {rule_id}" if rule_id else "Wazuh alert",
        rule_description,
        f"agent={agent_name}" if agent_name else "",
        f"location={location}" if location else "",
        _text(alert.get("full_log", "")),
    ]
    message = "; ".join(part for part in message_parts if part)

    timestamp = _first(alert.get("timestamp"), alert.get("@timestamp"), default=None)
    if timestamp is not None:
        try:
            timestamp = datetime.fromisoformat(
                _text(timestamp).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("Wazuh alert timestamp must be ISO 8601") from exc

    try:
        return EventIn(
            event_type=event_type,
            username=_text(username),
            source_ip=_text(source_ip),
            process_name=_text(process_name),
            command_line=_text(command_line),
            message=message,
            timestamp=timestamp,
        )
    except ValidationError as exc:
        raise ValueError(f"Wazuh alert could not be normalized: {exc}") from exc
