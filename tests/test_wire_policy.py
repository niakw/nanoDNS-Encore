"""Native tests for the actual DNS wire parser and mandatory policy."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class WirePolicy(unittest.TestCase):
    def test_all_sections_and_ambiguous_wire_names(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p/"ps5").mkdir()
            (p/"ps5"/"kernel.h").write_text("#pragma once\n#include <sys/types.h>\nint kernel_set_ucred_authid(pid_t, long long);\n")
            (p/"ps5"/"klog.h").write_text("#pragma once\nvoid klog_printf(const char *, ...);\n")
            src = p/"wire.c"
            src.write_text(r"""
#define _GNU_SOURCE
#define PLATFORM_PS5 1
#ifndef SYS_thr_set_name
#define SYS_thr_set_name 9999
#endif
#define main nanodns_payload_main
#include "main.c"
#undef main
#include <assert.h>
static size_t wire_name(uint8_t *p, const char *s) {
    size_t n=0;
    while(*s) {
        const char *dot=strchr(s,'.');
        size_t len=dot?(size_t)(dot-s):strlen(s);
        p[n++]=(uint8_t)len; memcpy(p+n,s,len);n+=len;
        if(!dot)break;
        s=dot+1;
    }
    p[n++]=0;return n;
}
static size_t response(uint8_t *p,int section,const char *target) {
    memset(p,0,512);
    write_u16(p+2,0x8180);write_u16(p+4,1);
    write_u16(p+6+2*section,1);
    size_t n=12+wire_name(p+12,"example.org");
    write_u16(p+n,1);write_u16(p+n+2,1);n+=4;
    p[n++]=0xc0;p[n++]=0x0c;
    write_u16(p+n,5);write_u16(p+n+2,1);write_u32(p+n+4,60);
    size_t len=wire_name(p+n+10,target);
    write_u16(p+n+8,(uint16_t)len);return n+10+len;
}
int main(void) {
    uint8_t p[512];dns_question_t q;
    assert(protected_domain_match("playstation.com"));
    assert(protected_domain_match("www.playstation.com"));
    assert(!protected_domain_match("example.org"));
    for(int section=0;section<3;++section) {
        size_t n=response(p,section,"www.playstation.com");
        assert(dns_parse_question(p,n,&q)==0);
        assert(dns_response_has_blocked_target(p,n,&q));
        n=response(p,section,"example.net");
        assert(dns_parse_question(p,n,&q)==0);
        assert(!dns_response_has_blocked_target(p,n,&q));
        assert(dns_response_has_blocked_target(p,n-1,&q));
    }
    size_t n=response(p,0,"example.net");
    p[15]=0;assert(dns_parse_question(p,n,&q)!=0);
    n=response(p,0,"example.net");
    p[15]='.';assert(dns_parse_question(p,n,&q)!=0);
    return 0;
}
""")
            exe = p/"wire"
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                "-ffunction-sections","-fdata-sections","-I",str(p),"-I",str(ROOT),
                str(src),"-Wl,--gc-sections","-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
