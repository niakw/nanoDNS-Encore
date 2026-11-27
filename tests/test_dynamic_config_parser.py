"""Exercise production load_config() with a real INI containing >128 entries."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]

class DynamicConfigParser(unittest.TestCase):
    def test_real_parser_loads_more_than_128_rules_and_exceptions(self):
        cc = shutil.which("cc")
        self.assertIsNotNone(cc)
        main_c = (ROOT / "main.c").as_posix()

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "ps5").mkdir()
            (root / "ps5" / "kernel.h").write_text(
                "#pragma once\n#include <sys/types.h>\n"
                "int kernel_set_ucred_authid(pid_t, long long);\n",
                encoding="utf-8",
            )
            (root / "ps5" / "klog.h").write_text(
                "#pragma once\nvoid klog_printf(const char *, ...);\n",
                encoding="utf-8",
            )

            ini = root / "large.ini"
            rules = [f"rule-{i:03d}.example.test=0.0.0.0" for i in range(4096)]
            exceptions = [f"except-{i:03d}.example.test" for i in range(4096)]
            body = (
                "[general]\n"
                "bind=127.0.0.1\n"
                "bind6=::1\n"
                "[upstream]\n"
                "server=76.76.2.0\n"
                "[overrides]\n" + "\n".join(rules) + "\n"
                "[exceptions]\n" + "\n".join(exceptions) + "\n"
            )
            self.assertLess(len(body.encode()), 4096 * 1024)
            ini.write_text(body, encoding="utf-8")

            harness = root / "parser.c"
            harness.write_text(textwrap.dedent(f"""
                #define _GNU_SOURCE
                #define PLATFORM_PS5 1
                #ifndef SYS_thr_set_name
                #define SYS_thr_set_name 9999
                #endif
                #define main nanodns_payload_main
                #include "{main_c}"
                #undef main

                int main(int argc, char **argv) {{
                    if (argc != 4) return 90;
                    size_t expected_rules = strtoul(argv[2], NULL, 10);
                    size_t expected_exceptions = strtoul(argv[3], NULL, 10);
                    app_config_t cfg = {{0}};
                    int rc = load_config(argv[1], &cfg);
                    if (expected_rules > MAX_RULES || expected_exceptions > MAX_EXCEPTIONS) {{
                        int saved = errno;
                        config_release(&cfg);
                        return rc != 0 && saved == E2BIG ? 0 : 19;
                    }}
                    if (rc != 0) return 10;
                    if (cfg.rule_count != expected_rules) return 11;
                    if (cfg.exception_count != expected_exceptions) return 12;
                    if (cfg.rule_capacity < cfg.rule_count) return 13;
                    if (cfg.exception_capacity < cfg.exception_count) return 14;
                    if (expected_rules == MAX_RULES && strcmp(cfg.rules[MAX_RULES-1].mask, "rule-4095.example.test")) return 15;
                    if (expected_exceptions == MAX_EXCEPTIONS && strcmp(cfg.exceptions[MAX_EXCEPTIONS-1].mask, "except-4095.example.test")) return 16;
                    config_release(&cfg);
                    if (cfg.rules || cfg.exceptions) return 17;
                    return 0;
                }}
            """), encoding="utf-8")

            exe = root / "parser"
            build = subprocess.run(
                [
                    cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-Wno-unused-variable",
                    "-ffunction-sections", "-fdata-sections",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-I", str(root), str(harness),
                    "-Wl,--gc-sections", "-o", str(exe),
                ],
                text=True, capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run(
                [str(exe), str(ini), "4096", "4096"],
                text=True, capture_output=True,
                env={"ASAN_OPTIONS": "detect_leaks=1",
                     "UBSAN_OPTIONS": "halt_on_error=1"},
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

            profile = ROOT / "nanodns4096.ini"
            actual_count = sum(1 for line in profile.read_text(encoding="utf-8").splitlines() if line.endswith("=0.0.0.0"))
            for path, nr, ne in [(profile, actual_count, 0)]:
                run = subprocess.run([str(exe), str(path), str(nr), str(ne)], text=True, capture_output=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            # Reject both count overflows, not silently truncate to 4096.
            for suffix, nr, ne in [(body.replace("[exceptions]", "overflow.example.test=0.0.0.0\n[exceptions]"), 4097, 4096), (body + "overflow.example.test\n", 4096, 4097)]:
                ini.write_text(suffix, encoding="utf-8")
                run = subprocess.run([str(exe), str(ini), str(nr), str(ne)], text=True, capture_output=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

if __name__ == "__main__":
    unittest.main()
