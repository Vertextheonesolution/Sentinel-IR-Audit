"""Input validation for deliberately small, offline JSONL observation records."""

from dataclasses import dataclass
from typing import Any

KINDS = frozenset(("process", "scheduled_task", "startup_entry"))
FIELDS = {
    "process": ("name", "executable_path", "command_line", "parent_name"),
    "scheduled_task": ("task_name", "executable", "arguments", "task_path"),
    "startup_entry": ("name", "command", "registry_key"),
}
IDENTIFIERS = {
    "process": "name",
    "scheduled_task": "task_name",
    "startup_entry": "name",
}
MAX_FIELD_LENGTH = 8192


class ObservationError(ValueError):
    """Raised when an observation is invalid or cannot be analyzed safely."""


@dataclass(frozen=True)
class Observation:
    kind: str
    index: int
    entity: str
    fields: dict[str, str]
    timestamp: str | None

    def get(self, key: str) -> str:
        return self.fields.get(key, "")


def parse_observation(record: Any, index: int) -> Observation:
    if not isinstance(record, dict):
        raise ObservationError("record must be a JSON object")
    kind = record.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        raise ObservationError("kind must be process, scheduled_task, or startup_entry")

    fields: dict[str, str] = {}
    for key in FIELDS[kind]:
        value = record.get(key, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ObservationError(f"{key} must be a string")
        if len(value) > MAX_FIELD_LENGTH:
            raise ObservationError(f"{key} exceeds {MAX_FIELD_LENGTH} characters")
        fields[key] = value.strip()

    identifier = fields[IDENTIFIERS[kind]]
    if not identifier:
        raise ObservationError(f"{IDENTIFIERS[kind]} is required")

    timestamp = record.get("timestamp")
    if timestamp is not None and (
        not isinstance(timestamp, str) or len(timestamp) > 64
    ):
        raise ObservationError("timestamp must be a short ISO 8601 string")

    # Do not retain unknown fields, nested data, or the raw input record.
    # An entity label is intentionally short and stripped of control characters.
    safe_entity = "".join(ch for ch in identifier if ch.isprintable())[:160]
    return Observation(kind, index, safe_entity, fields, timestamp)
