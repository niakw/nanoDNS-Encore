"""Validate the optional extended profile without making it the release default."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "nanodns.ini"
EXT = ROOT / "nanodns512.ini"

def parse(path):
    section = None
    rules = []
    exceptions = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if section == "overrides":
            if "=" not in line:
                raise AssertionError(f"malformed override: {line}")
            rules.append(tuple(line.split("=", 1)))
        elif section == "exceptions":
            exceptions.append(line.split("=", 1)[0])
    return rules, exceptions

class ExtendedProfileTests(unittest.TestCase):
    def test_extended_profile_is_a_superset_not_the_canonical_policy(self):
        base, base_exc = parse(BASE)
        extended, ext_exc = parse(EXT)
        self.assertEqual(len(base), 124)
        self.assertEqual(len(extended), 233)
        self.assertEqual(base_exc, [])
        self.assertEqual(ext_exc, [])
        self.assertEqual(extended[:len(base)], base)
        self.assertEqual(len({m for m, _ in extended}), len(extended))
        self.assertTrue(all(ip == "0.0.0.0" for _, ip in extended))
        self.assertLess(EXT.stat().st_size, 64 * 1024)

    def test_extended_profile_is_never_packaged_as_default(self):
        for rel in (
            ".github/workflows/publish-rc.yml",
            ".github/workflows/package-install-zip.yml",
        ):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("nanodns.ini", text)
            self.assertNotIn("nanodns512.ini", text)

    def test_header_marks_profile_optional_and_unqualified(self):
        header = "\n".join(EXT.read_text(encoding="utf-8").splitlines()[:16]).lower()
        self.assertIn("optional", header)
        self.assertIn("not hardware-qualified", header)
        self.assertIn("233 overrides", header)

if __name__ == "__main__":
    unittest.main()
