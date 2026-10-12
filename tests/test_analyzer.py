"""Unit tests using fictional security observations only."""

import unittest

from sentinel_ir_audit.analyzer import analyze
from sentinel_ir_audit.schema import ObservationError, parse_observation


def flags(data: dict) -> set[str]:
    return {item.rule_id for item in analyze(parse_observation(data, 1))}


class AnalyzerTests(unittest.TestCase):
    def test_encoded_powershell_command(self) -> None:
        self.assertIn("SIA-002", flags({"kind": "process", "name": "powershell.exe", "command_line": "powershell.exe -EncodedCommand QQ=="}))

    def test_encoded_powershell_without_command_details_is_not_assumed(self) -> None:
        self.assertNotIn("SIA-002", flags({"kind": "process", "name": "powershell.exe", "command_line": ""}))

    def test_encoded_switch_in_unrelated_process_not_flagged(self) -> None:
        self.assertNotIn("SIA-002", flags({"kind": "process", "name": "python.exe", "command_line": "python.exe -enc utf-8"}))

    def test_startup_hidden_interpreter(self) -> None:
        result = flags({"kind": "startup_entry", "name": "test", "command": "powershell.exe -WindowStyle Hidden -File C:\\Tools\\job.ps1"})
        self.assertIn("SIA-003", result)

    def test_temp_scheduled_task(self) -> None:
        self.assertIn("SIA-001", flags({"kind": "scheduled_task", "task_name": "t", "executable": "C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe"}))

    def test_windows_temp_process(self) -> None:
        self.assertIn("SIA-001", flags({"kind": "process", "name": "x.exe", "executable_path": "C:\\Windows\\Temp\\x.exe"}))

    def test_env_temp_task(self) -> None:
        self.assertIn("SIA-001", flags({"kind": "scheduled_task", "task_name": "t", "executable": "%TEMP%\\x.exe"}))

    def test_non_temp_similar_name_is_not_flagged(self) -> None:
        self.assertNotIn("SIA-001", flags({"kind": "process", "name": "x.exe", "executable_path": "C:\\Tools\\TempFiles\\x.exe"}))

    def test_system_process_masquerade(self) -> None:
        self.assertIn("SIA-004", flags({"kind": "process", "name": "svchost.exe", "executable_path": "C:\\Users\\Example\\Downloads\\svchost.exe"}))

    def test_system_process_system32_path(self) -> None:
        self.assertNotIn("SIA-004", flags({"kind": "process", "name": "svchost.exe", "executable_path": "C:\\Windows\\System32\\svchost.exe"}))

    def test_system_process_unknown_path_not_flagged(self) -> None:
        self.assertNotIn("SIA-004", flags({"kind": "process", "name": "svchost.exe", "executable_path": ""}))

    def test_startup_downloads(self) -> None:
        self.assertIn("SIA-005", flags({"kind": "startup_entry", "name": "test", "command": "C:\\Users\\Example\\Downloads\\setup.exe"}))

    def test_legitimate_task_not_flagged(self) -> None:
        self.assertEqual(flags({"kind": "scheduled_task", "task_name": "Backup", "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "arguments": "-NoProfile -File C:\\Scripts\\backup.ps1"}), set())

    def test_missing_required_identifier(self) -> None:
        with self.assertRaises(ObservationError):
            parse_observation({"kind": "process", "name": ""}, 1)

    def test_non_string_field_is_rejected(self) -> None:
        with self.assertRaises(ObservationError):
            parse_observation({"kind": "process", "name": "demo", "command_line": ["fake"]}, 1)

    def test_unknown_kind_is_rejected(self) -> None:
        with self.assertRaises(ObservationError):
            parse_observation({"kind": "remote_exec", "name": "test"}, 1)

    def test_control_chars_removed_from_entity(self) -> None:
        item = parse_observation({"kind": "process", "name": "x\n\r\t.exe"}, 1)
        self.assertEqual(item.entity, "x.exe")

    def test_raw_command_not_in_finding(self) -> None:
        observation = parse_observation({"kind": "process", "name": "powershell.exe", "command_line": "powershell.exe -enc secret_private_string"}, 1)
        items = analyze(observation)
        self.assertTrue(items)
        self.assertNotIn("secret_private_string", str([x.to_jsonable() for x in items]))

    def test_multiple_findings_for_same_observation(self) -> None:
        item = flags({"kind": "startup_entry", "name": "t", "command": "powershell.exe -WindowStyle Hidden -File C:\\Users\\Example\\AppData\\Local\\Temp\\demo.ps1"})
        self.assertEqual(item, {"SIA-001", "SIA-003"})


if __name__ == "__main__":
    unittest.main()
