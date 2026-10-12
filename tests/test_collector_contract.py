"""Static guardrails; not a substitute for Windows PowerShell runtime tests."""

from pathlib import Path
import re
import unittest

COLLECTOR = Path(__file__).resolve().parents[1] / "collectors" / "Collect-WindowsSnapshot.ps1"


class CollectorContractTests(unittest.TestCase):
    def test_only_inventory_operations_are_referenced(self) -> None:
        script = COLLECTOR.read_text(encoding="utf-8")
        for command in ("Get-CimInstance", "Get-ScheduledTask", "Get-ItemProperty"):
            self.assertIn(command, script)
        for forbidden in ("Stop-Process", "Unregister-ScheduledTask", "Remove-Item", "Set-ItemProperty", "Invoke-WebRequest", "Invoke-RestMethod", "Start-Process", "Invoke-Expression"):
            self.assertIsNone(re.search(r"(?im)^\s*" + re.escape(forbidden) + r"\b", script), forbidden)

    def test_sensitive_command_details_require_switch(self) -> None:
        script = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn("[switch]$IncludeCommandDetails", script)
        self.assertIn("if ($IncludeCommandDetails)", script)
        self.assertIn("$utf8NoBom", script)


if __name__ == "__main__":
    unittest.main()
