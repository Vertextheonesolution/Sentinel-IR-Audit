"""Deterministic, non-executing heuristics for offline Windows observations.

These are triage signals, not proof of compromise. No commands from input run.
"""

from dataclasses import asdict, dataclass
import ntpath
import re

from .schema import Observation


# Source artifacts have already been sanitized by the input schema.
TEMP_PATH = re.compile(
    r"(?i)(?:[a-z]:\\windows\\temp\\|"
    r"[a-z]:\\users\\[^\\\s]+\\appdata\\local\\temp\\|"
    r"[a-z]:\\temp\\|%temp%\\|\$env:temp\\)"
)
DOWNLOAD_PATH = re.compile(r"(?i)[a-z]:\\users\\[^\\\s]+\\downloads\\")
ENCODED_PS = re.compile(r"(?i)(?:^|\s)[-/](?:enc|encodedcommand)(?=$|[\s:=])")
HIDDEN_WINDOW = re.compile(
    r"(?i)(?:^|\s)[-/](?:windowstyle|w)(?:\s+|:)(?:hidden|hid)(?=$|\s)"
)
POWERSHELL = re.compile(r"(?i)(?<![a-z0-9_])(?:powershell|pwsh)(?:\.exe)?\b")
SCRIPT_HOST = re.compile(
    r"(?i)(?<![a-z0-9_])(?:powershell|pwsh|wscript|cscript|mshta)(?:\.exe)?\b"
)
SYSTEM_PROCESSES = frozenset(("svchost.exe", "lsass.exe", "services.exe", "winlogon.exe"))
TRUSTED_SYSTEM_PATH = re.compile(
    r"(?i)^(?:[a-z]:\\windows\\(?:system32|syswow64)|"
    r"%(?:windir|systemroot)%\\(?:system32|syswow64))\\([^\\]+)$"
)



@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    rationale: str
    recommendation: str
    mitre_attack: tuple[str, ...]
    record_index: int
    kind: str
    entity: str
    matched_fields: tuple[str, ...]
    timestamp: str | None

    def to_jsonable(self) -> dict[str, object]:
        item = asdict(self)
        item["mitre_attack"] = list(self.mitre_attack)
        item["matched_fields"] = list(self.matched_fields)
        return item


def _windows_path(value: str) -> str:
    return value.strip().strip('"\'').replace("/", "\\").lower()


def _trusted_system_image_path(path: str, expected_name: str) -> bool:
    """Normalize Windows directory traversals and check the actual image filename."""
    normalized = ntpath.normpath(_windows_path(path))
    match = TRUSTED_SYSTEM_PATH.fullmatch(normalized)
    return bool(match and match.group(1).lower() == expected_name.lower())


def _command_text(obs: Observation) -> str:
    if obs.kind == "process":
        return obs.get("command_line")
    if obs.kind == "scheduled_task":
        return " ".join((obs.get("executable"), obs.get("arguments")))
    return obs.get("command")


def _has_powershell(obs: Observation) -> bool:
    if obs.kind == "process" and obs.get("name").lower() in ("powershell.exe", "pwsh.exe"):
        return True
    if obs.kind == "scheduled_task" and POWERSHELL.search(obs.get("executable")):
        return True
    return bool(POWERSHELL.search(_command_text(obs)))


def _attack_for_persistence(obs: Observation) -> tuple[str, ...]:
    if obs.kind == "scheduled_task":
        return ("T1053.005",)
    if obs.kind == "startup_entry":
        return ("T1547.001",)
    return ()


def _make(
    obs: Observation,
    rule_id: str,
    severity: str,
    title: str,
    rationale: str,
    recommendation: str,
    matched_fields: tuple[str, ...],
    mitre_attack: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        rationale=rationale,
        recommendation=recommendation,
        mitre_attack=mitre_attack,
        record_index=obs.index,
        kind=obs.kind,
        entity=obs.entity,
        matched_fields=matched_fields,
        timestamp=obs.timestamp,
    )


def analyze(obs: Observation) -> list[Finding]:
    """Return conservative indicators for one observation; never run input."""
    results: list[Finding] = []
    cmd = _command_text(obs)
    if obs.kind == "process":
        candidate = obs.get("executable_path")
        temp_candidate = candidate
        matched = ("executable_path",)
    elif obs.kind == "scheduled_task":
        candidate = obs.get("executable")
        temp_candidate = " ".join((candidate, obs.get("arguments")))
        matched = ("executable", "arguments")
    else:
        candidate = obs.get("command")
        temp_candidate = candidate
        matched = ("command",)

    if TEMP_PATH.search(_windows_path(temp_candidate)):
        results.append(_make(
            obs, "SIA-001", "high" if obs.kind != "process" else "medium",
            "Execution reference in a temporary directory",
            "A process or persistence entry references a temporary, user-writable directory.",
            "Verify the file origin, signer, hash, and approved change context before taking action.",
            matched, _attack_for_persistence(obs),
        ))

    if _has_powershell(obs) and ENCODED_PS.search(cmd):
        results.append(_make(
            obs, "SIA-002", "medium", "Encoded PowerShell command",
            "An encoded command-line switch was observed in a PowerShell context.",
            "Review the authorized task or script source in a controlled environment; do not execute unknown payloads.",
            ("command_line",) if obs.kind == "process" else (("arguments",) if obs.kind == "scheduled_task" else ("command",)),
            ("T1059.001",),
        ))

    if obs.kind in ("scheduled_task", "startup_entry") and SCRIPT_HOST.search(cmd) and HIDDEN_WINDOW.search(cmd):
        results.append(_make(
            obs, "SIA-003", "medium", "Hidden script host in a persistence entry",
            "A scheduled task or startup entry references a script host with a hidden-window switch.",
            "Confirm business justification and review the task owner and full definition locally.",
            ("arguments",) if obs.kind == "scheduled_task" else ("command",),
            _attack_for_persistence(obs),
        ))

    if obs.kind == "process":
        name = obs.get("name").lower()
        path = _windows_path(obs.get("executable_path"))
        if name in SYSTEM_PROCESSES and path and not _trusted_system_image_path(path, name):
            results.append(_make(
                obs, "SIA-004", "high", "System process name outside an expected Windows directory",
                "A process uses a Windows system process name but has an unexpected executable location.",
                "Verify the image path and signature, collect forensic context, and escalate for analyst review.",
                ("name", "executable_path"), ("T1036.005",),
            ))

    if obs.kind in ("scheduled_task", "startup_entry") and DOWNLOAD_PATH.search(_windows_path(temp_candidate)):
        results.append(_make(
            obs, "SIA-005", "medium", "Persistence entry references Downloads",
            "The persistence entry references an executable or script beneath a user's Downloads directory.",
            "Confirm whether this path is approved for long-running execution and investigate its provenance.",
            matched, _attack_for_persistence(obs),
        ))

    return results
