import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from sentinel_ir_audit.cli import main, scan

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "synthetic-windows-observations.jsonl"


class CliTests(unittest.TestCase):
    def test_fixture_has_expected_observations(self) -> None:
        findings, summary = scan(FIXTURE)
        self.assertEqual(summary["observations"], 7)
        self.assertGreaterEqual(len(findings), 5)
        self.assertEqual(summary["findings"], len(findings))
        self.assertEqual(summary["severity_counts"]["high"], 3)

    def test_successful_scan_generates_jsonl_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.jsonl"
            summary = Path(directory) / "summary.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["scan", "--input", str(FIXTURE), "--output", str(output), "--summary", str(summary)])
            self.assertEqual(status, 0)
            rows = [json.loads(x) for x in output.read_text().splitlines()]
            self.assertEqual(len(rows), json.loads(summary.read_text())["findings"])
            self.assertTrue(all("command_line" not in row for row in rows))

    def test_fail_on_high_returns_three_but_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.jsonl"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["scan", "--input", str(FIXTURE), "--output", str(output), "--fail-on", "high"])
            self.assertEqual(status, 3)
            self.assertTrue(output.exists())

    def test_output_must_not_overwrite_input(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            status = main(["scan", "--input", str(FIXTURE), "--output", str(FIXTURE)])
        self.assertEqual(status, 2)

    def test_malformed_json_creates_no_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text('{"kind":"process","name":"safe.exe"}\n{bad json}\n')
            output = Path(directory) / "out.jsonl"
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(["scan", "--input", str(bad), "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())

    def test_nonobject_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text("[]\n")
            with self.assertRaisesRegex(Exception, "invalid observation"):
                scan(bad)

    def test_existing_output_requires_explicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.jsonl"
            output.write_text("existing data")
            with contextlib.redirect_stderr(io.StringIO()):
                denied = main(["scan", "--input", str(FIXTURE), "--output", str(output)])
            self.assertEqual(denied, 2)
            self.assertEqual(output.read_text(), "existing data")
            with contextlib.redirect_stdout(io.StringIO()):
                allowed = main(["scan", "--input", str(FIXTURE), "--output", str(output), "--overwrite"])
            self.assertEqual(allowed, 0)
            self.assertNotEqual(output.read_text(), "existing data")

    def test_duplicate_kind_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text('{"kind":"process","kind":"scheduled_task","name":"demo","task_name":"t"}\n')
            with self.assertRaisesRegex(Exception, "invalid observation"):
                scan(bad)

    def test_nested_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text('{"kind":"process","name":"demo","unknown":{"x":1,"x":2}}\n')
            with self.assertRaisesRegex(Exception, "invalid observation"):
                scan(bad)

    def test_missing_input_creates_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent.jsonl"
            output = Path(directory) / "out.jsonl"
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(["scan", "--input", str(missing), "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())

    def test_unhashable_kind_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text('{"kind":[],"name":"demo"}\n')
            with self.assertRaisesRegex(Exception, "invalid observation"):
                scan(bad)

    def test_large_line_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text(' ' * (130 * 1024) + '\n')
            with self.assertRaisesRegex(Exception, "exceeds"):
                scan(bad)


if __name__ == "__main__":
    unittest.main()
