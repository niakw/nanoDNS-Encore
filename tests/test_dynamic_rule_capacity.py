"""Compile the production dynamic rule-storage functions and prove >128 entries work."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
C = (ROOT / "main.c").read_text(encoding="utf-8")

def extract(pattern, name):
    m = re.search(pattern, C, re.S | re.M)
    if not m:
        raise AssertionError(f"cannot extract {name}")
    return m.group(0)

class DynamicRuleCapacity(unittest.TestCase):
    def test_production_rule_storage_accepts_more_than_128(self):
        cc = shutil.which("cc")
        self.assertIsNotNone(cc)

        defines = "\n".join(
            extract(rf"^#define {name} .*$", name)
            for name in (
                "MAX_UPSTREAMS", "MAX_EXCEPTIONS", "INITIAL_RULE_CAPACITY",
                "MAX_CONFIG_WARNINGS", "MAX_CONFIG_WARNING_LEN",
                "MAX_DOMAIN_LEN", "MAX_LOG_PATH",
            )
        )
        structs = extract(
            r"typedef struct \{\n  struct in_addr addr;.*?\n\} app_config_t;",
            "configuration structs",
        )
        normalize = extract(
            r"static void\nnormalize_domain\(.*?\n\}",
            "normalize_domain",
        )
        release = extract(
            r"static void\nconfig_release\(.*?\n\}",
            "config_release",
        )
        add = extract(
            r"static int\nconfig_add_rule\(.*?\n\}",
            "config_add_rule",
        )

        harness = r'''
int main(void) {
    app_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    char mask[64];
    for (int i = 0; i < 512; ++i) {
        snprintf(mask, sizeof(mask), "rule-%03d.example.test", i);
        if (config_add_rule(&cfg, mask, "0.0.0.0") != 0) return 10;
    }
    if (cfg.rule_count != 512) return 11;
    if (cfg.rule_capacity < cfg.rule_count) return 12;
    if (strcmp(cfg.rules[0].mask, "rule-000.example.test") != 0) return 13;
    if (strcmp(cfg.rules[511].mask, "rule-511.example.test") != 0) return 14;
    config_release(&cfg);
    if (cfg.rules != NULL || cfg.rule_count != 0 || cfg.rule_capacity != 0) return 15;
    return 0;
}
'''
        source = """#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
""" + defines + "\n" + structs + "\n" + normalize + "\n" + release + "\n" + add + "\n" + harness

        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "capacity.c"
            exe = Path(d) / "capacity"
            src.write_text(source, encoding="utf-8")
            build = subprocess.run(
                [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 str(src), "-o", str(exe)],
                text=True, capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run(
                [str(exe)], text=True, capture_output=True,
                env={"ASAN_OPTIONS": "detect_leaks=1", "UBSAN_OPTIONS": "halt_on_error=1"},
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

if __name__ == "__main__":
    unittest.main()
