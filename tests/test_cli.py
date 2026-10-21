import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_documented_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "demo.db")

            def run(*args):
                return subprocess.run(
                    [sys.executable, "-m", "securefi", "--db", db, *args],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

            self.assertEqual(run("demo").returncode, 0)
            blocked = run("gate")
            self.assertEqual(blocked.returncode, 2)
            self.assertFalse(json.loads(blocked.stdout)["passed"])
            for kind, file in [
                ("normalized", "findings.json"),
                ("sarif", "sast.sarif"),
                ("cyclonedx", "sbom.json"),
                ("cloud", "cloud.json"),
                ("events", "events.json"),
            ]:
                self.assertEqual(
                    run(
                        "import", kind, str(ROOT / "examples" / file), "--asset", "1"
                    ).returncode,
                    0,
                )
            export = str(Path(directory) / "snapshot.json")
            self.assertEqual(run("export", export).returncode, 0)
            self.assertGreater(len(json.loads(Path(export).read_text())["findings"]), 8)
            self.assertEqual(run("export", export).returncode, 1)
            self.assertEqual(run("demo").returncode, 1)
            self.assertNotIn(
                "Traceback",
                run("import", "sarif", "missing.json", "--asset", "1").stderr,
            )
