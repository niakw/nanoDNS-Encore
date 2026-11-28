"""Exercise the production path selector without network or console."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ConfigSelection(unittest.TestCase):
    def test_priority_absence_and_invalid_preferred(self):
        src = (ROOT / "main.c").read_text()
        start = src.index("static int\nselect_config_path(")
        end = src.index("\nstatic int\nensure_default_config_exists(", start)
        harness = """#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
""" + src[start:end] + """
int main(int argc, char **argv) {
    if(argc != 3) return 2;
    const char *selected;
    int rc = select_config_path(argv[1], argv[2], &selected);
    printf("%d %s\\n", rc, selected);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, binary = root / "select.c", root / "select"
            source.write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(source), "-o", str(binary)], check=True)
            preferred, legacy = root / "nanodns4096.ini", root / "nanodns.ini"
            def select():
                return subprocess.check_output([str(binary), str(preferred), str(legacy)], text=True).strip()
            self.assertEqual(select(), f"1 {preferred}")
            legacy.write_text("legacy")
            self.assertEqual(select(), f"0 {legacy}")
            preferred.write_text("preferred")
            self.assertEqual(select(), f"0 {preferred}")
            preferred.unlink()
            preferred.symlink_to(root / "missing")
            self.assertEqual(select(), f"0 {preferred}")
            preferred.unlink()
            preferred.mkdir()
            self.assertEqual(select(), f"0 {preferred}")

    def test_single_parser_and_candidate_package(self):
        src = (ROOT / "main.c").read_text().split("main(void) {", 1)[1]
        self.assertEqual(src.count("load_config("), 1)
        self.assertIn("load_config(config_path, &cfg)", src)
        self.assertIn("if(selection == 1)", src)
        wf = (ROOT / ".github/workflows/ps5.yml").read_text()
        self.assertIn("cp nanodns4096.ini candidate/data/nanodns/nanodns4096.ini", wf)
        self.assertNotIn("candidate/data/nanodns/nanodns.ini", wf)
