"""Verify that the PS5 binary's mandatory blocklist matches the shipped INI.
No network access or PS5 SDK required.
"""
import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
C = (ROOT / "main.c").read_text(encoding="utf-8")
INI = (ROOT / "nanodns.ini").read_text(encoding="utf-8")
EXT = (ROOT / "nanodns4096.ini").read_text(encoding="utf-8")
EXAMPLE = (ROOT / "nanodns.ini.example").read_text(encoding="utf-8")


def get_rules(text):
    section = ""
    rules = []
    exceptions = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if section == "overrides":
            if "=" not in line:
                raise AssertionError("Malformed rule: " + line)
            rules.append(tuple(line.split("=", 1)))
        if section == "exceptions":
            exceptions.append(line)
    return rules, exceptions


def embedded_masks():
    match = re.search(
        r"static const char \*const k_protected_masks\[\] = \{(.*?)\n\};",
        C, re.S,
    )
    if not match:
        raise AssertionError("Missing compiled mandatory blocklist")
    return [
        ast.literal_eval(line.strip().rstrip(","))
        for line in match.group(1).splitlines() if line.strip()
    ]


def embedded_default():
    match = re.search(
        r"static const char \*k_default_config =\n(.*?);\n\n",
        C, re.S,
    )
    if not match:
        raise AssertionError("Missing default INI")
    chunks = re.findall(r'^\s*("(?:[^"\\]|\\.)*")\s*$', match.group(1), re.M)
    return "".join(ast.literal_eval(c) for c in chunks)


class PolicyIntegrityTests(unittest.TestCase):
    def test_canonical_profile(self):
        rules, exceptions = get_rules(INI)
        self.assertEqual(len(rules), 124)
        self.assertEqual(exceptions, [])
        self.assertTrue(all(ip == "0.0.0.0" for _, ip in rules))
        self.assertEqual(len(set(mask for mask, _ in rules)), 124)
        self.assertEqual((rules, exceptions), get_rules(EXAMPLE))

    def test_binary_mandatory_rules_are_identical(self):
        masks = [m for m, _ in get_rules(EXT)[0]]
        self.assertEqual(len(masks), 1719)
        self.assertEqual(embedded_masks(), masks)

    def test_builtin_defaults_identical_to_shipped_rules(self):
        self.assertEqual(get_rules(embedded_default()), get_rules(EXT))

    def test_fail_closed_before_exceptions(self):
        a = C.index("if(protected_domain_match(question.qname))")
        b = C.index("else if(has_matching_exception(cfg, question.qname))")
        c = C.index("forward_query_to_upstream(cfg, request")
        self.assertLess(a, b)
        self.assertLess(b, c)
        self.assertIn("question.qdcount != 1 || question.qclass != 1", C)
        self.assertIn("dns_response_has_blocked_target(response", C)
        self.assertNotIn("terminate_existing_instances(", C)
        self.assertNotIn("SO_REUSEADDR", C)

    def test_blocked_query_never_falls_through_to_upstream(self):
        start = C.index("if(rule != NULL) {", C.index("handle_dns_request("))
        end = C.index("forward_query_to_upstream(cfg, request", start)
        block = C[start:end]
        self.assertRegex(block, r'dropping %s without upstream\\n",\s*question.qname\);\s*return;\s*\}')
        self.assertIn("build_nodata_response", block)
        self.assertIn("override-servfail", block)

    def test_resident_label_is_distinct_from_installation_path(self):
        self.assertIn('#define PAYLOAD_PROCESS_LABEL "nanodns-encore"', C)
        self.assertIn("syscall(SYS_thr_set_name, -1, PAYLOAD_PROCESS_LABEL)", C)
        self.assertIn("process-label=%s thread-name-rc=%ld errno=%d pid=%ld", C)
        self.assertIn("ELF := nanodns.elf", (ROOT / "Makefile").read_text())

    def test_ordered_four_upstream_defaults(self):
        def upstreams(ini):
            section = ""
            names = []
            for raw in ini.splitlines():
                line = raw.split("#", 1)[0].strip()
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].lower()
                elif section == "upstream" and line.startswith("server="):
                    names.append(line)
            return names
        expected = ["server=76.76.2.0", "server=76.76.10.0", "server=94.140.14.140", "server=94.140.14.141"]
        self.assertEqual(upstreams(INI), expected)
        self.assertEqual(upstreams(EXAMPLE), expected)
        self.assertEqual(upstreams(embedded_default()), expected)
        builtin = C.split("config_apply_builtin_upstreams(app_config_t *cfg) {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(re.findall(r'config_add_upstream\(cfg, "([^"]+)"\)', builtin), ["76.76.2.0", "76.76.10.0", "94.140.14.140", "94.140.14.141"])
        self.assertNotIn('"9.9.9.9"', C)
        self.assertNotIn('"149.112.112.112"', C)
        self.assertNotIn('config_add_upstream(cfg, "1.1.1.1")', C)

    def test_credit_and_license(self):
        self.assertIn("github.com/niakw/nanodns-console-blocklist", INI)
        self.assertIn("github.com/drakmor/nanoDNS", INI)
        self.assertTrue((ROOT / "LICENSE").exists())
        self.assertIn("GNU GENERAL PUBLIC LICENSE", (ROOT / "LICENSE").read_text())


if __name__ == "__main__":
    unittest.main()
