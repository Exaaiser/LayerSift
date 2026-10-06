#!/usr/bin/env python3
"""Exercise the public demo files against the real CLI, using only Python's standard library."""
import argparse
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cli", type=pathlib.Path, default=root / "target" / "release" / ("layersift.exe" if sys.platform == "win32" else "layersift"))
args = parser.parse_args()
cli = str(args.cli.resolve())
manifest = json.loads((root / "examples" / "expected.json").read_text())
for case in manifest["cases"]:
    output = subprocess.check_output([cli, "inspect", "--file", str(root / "examples" / case["file"]), "--json", *case["args"]], text=True)
    artifacts = json.loads(output)["artifacts"]
    matching = [item for item in artifacts if item["sha256"] == case["sha256"] and item["steps"][-len(case["steps"]):] == case["steps"]]
    if not matching:
        raise SystemExit(f"FAIL: {case['file']} did not recover the expected content and steps")
    print(f"PASS: {case['file']}")
expected = (root / "examples" / "checksum.sha256").read_text().strip()
subprocess.run([cli, "hash", "verify", "sha256", expected, "--file", str(root / "examples" / "checksum.txt")], check=True)
print("PASS: checksum.txt matches checksum.sha256")
