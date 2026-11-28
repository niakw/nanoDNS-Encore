"""Validate the 0.4-13.60.4 extended release profile and legacy compatibility."""
from pathlib import Path
import unittest
import fnmatch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "nanodns.ini"
EXT = ROOT / "nanodns4096.ini"

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
    def test_release_profile_preserves_canonical_prefix(self):
        base, base_exc = parse(BASE)
        extended, ext_exc = parse(EXT)
        self.assertEqual(len(base), 124)
        self.assertGreaterEqual(len(extended), 1719)
        self.assertLessEqual(len(extended), 4096)
        self.assertEqual(base_exc, [])
        self.assertEqual(ext_exc, [])
        self.assertEqual(extended[:len(base)], base)
        self.assertEqual(len({m for m, _ in extended}), len(extended))
        self.assertTrue(all(ip == "0.0.0.0" for _, ip in extended))
        self.assertLess(EXT.stat().st_size, 4096 * 1024)

    def test_release_and_historical_packaging_are_separate(self):
        publisher = (ROOT / ".github/workflows/publish-rc.yml").read_text(encoding="utf-8")
        historical = (ROOT / ".github/workflows/package-install-zip.yml").read_text(encoding="utf-8")
        self.assertIn("nanodns4096.ini", publisher)
        self.assertIn("v0.4-13.60.4", publisher)
        self.assertIn("nanodns.ini", historical)
        self.assertNotIn("nanodns4096.ini", historical)

    def test_header_marks_profile_as_release_and_user_tested(self):
        header = "\n".join(EXT.read_text(encoding="utf-8").splitlines()[:16]).lower()
        self.assertIn("0.4-13.60.4", header)
        self.assertIn("user-tested", header)
        self.assertIn("runtime capacity 4096", header)
        self.assertNotIn("not hardware-qualified", header)

    def test_publisher_families_and_shared_service_negatives(self):
        rules, _ = parse(EXT)
        masks = [mask for mask, _ in rules]
        def blocked(name):
            return any(fnmatch.fnmatchcase(name, mask) for mask in masks)
        for domain in ("activision.com", "bungie.net", "riotgames.com", "pvp.net", "game.qq.com", "hoyoverse.com", "steamcontent.com", "garena.com", "hoodedhorse.com", "playfabapi.com"):
            self.assertTrue(blocked(domain), domain)
            self.assertTrue(blocked("api." + domain), domain)
        for domain in ("github.com", "api.github.com", "google.com", "amazonaws.com", "cloudfront.net", "akamaized.net", "qq.com", "login.microsoft.com", "example.org"):
            self.assertFalse(blocked(domain), domain)
        self.assertFalse((ROOT / "nanodns512.ini").exists())

if __name__ == "__main__":
    unittest.main()
