"""Run the production forwarding loop against deterministic host socket stubs."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
typedef struct { char text[32]; } upstream_t;
typedef struct { size_t upstream_count; int timeout_ms; upstream_t upstreams[4]; } app_config_t;
typedef struct { uint16_t id, flags, qdcount, qtype, qclass; char qname[32]; } dns_question_t;
static int g_running = 1;
static int64_t clock_ms;
static int outcomes[4], calls[4], active;
static dns_question_t requested = {42, 0, 1, 1, 1, "example.org"};
static int64_t now_ms(void) { return clock_ms; }
static int open_upstream_socket(const upstream_t *u) { return u->text[0] - '0'; }
static int drain_upstream_socket(int fd) { (void)fd; return 0; }
static void close_upstream_socket(int *fd) { *fd = -1; }
#define log_printf(...) ((void)0)
static ssize_t fake_send(int fd, const void *b, size_t n, int flags) {
    (void)b; (void)flags; calls[fd]++; return (ssize_t)n;
}
static int fake_poll(struct pollfd *p, nfds_t count, int timeout) {
    assert(count == 1); assert(timeout == 1500);
    if (outcomes[p->fd] < 0) { clock_ms += timeout; return 0; }
    p->revents = POLLIN; return 1;
}
static ssize_t fake_recv(int fd, void *b, size_t n, int flags) {
    (void)flags; assert(n >= 12); memset(b, 0, 12); active = fd; return 12;
}
static uint16_t read_u16(const uint8_t *b) { (void)b; return 42; }
static int dns_parse_question(const uint8_t *b, size_t n, dns_question_t *q) {
    (void)b; (void)n; *q = requested; q->flags = 0x8000 | outcomes[active]; return 0;
}
static int dns_response_has_blocked_target(const uint8_t *b, size_t n, const dns_question_t *q) {
    (void)b; (void)n; (void)q; return 0;
}
#define send fake_send
#define poll fake_poll
#define recv fake_recv
'''

HARNESS = r'''
static void run_case(int a, int b, int c, int d, int expected, int n_calls, int elapsed) {
    app_config_t cfg = {4, 1500, {{"0"}, {"1"}, {"2"}, {"3"}}};
    uint8_t req[12] = {0}, resp[512];
    size_t len = 0;
    char via[32] = {0};
    int fds[4] = {-1,-1,-1,-1};
    outcomes[0]=a; outcomes[1]=b; outcomes[2]=c; outcomes[3]=d;
    memset(calls, 0, sizeof(calls)); clock_ms=0;
    int rc = forward_query_to_upstream(&cfg,req,sizeof(req),&requested,fds,resp,sizeof(resp),&len,via,sizeof(via));
    if (expected < 0) assert(rc == -1);
    else { assert(rc == 0); assert(via[0] == '0'+expected); assert(len == 12); }
    for (int i=0;i<4;i++) assert(calls[i] == (i<n_calls));
    assert(clock_ms == elapsed);
}
int main(void) {
    run_case(0,0,0,0,0,1,0);
    run_case(-1,-1,0,0,2,3,3000);
    run_case(-1,-1,-1,0,3,4,4500);
    run_case(2,5,0,0,2,3,0);
    run_case(3,0,0,0,0,1,0);
    run_case(-1,-1,-1,-1,-1,4,6000);
    return 0;
}
'''

class ForwardingFailover(unittest.TestCase):
    def test_production_loop_order_and_deadlines(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "host compiler required")
        src = (ROOT / "main.c").read_text(encoding="utf-8")
        start = src.index("static int\nforward_query_to_upstream(")
        end = src.index("\nstatic void\nsend_dns_response_to_client(", start)
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            source = p / "failover.c"
            binary = p / "failover"
            source.write_text(STUBS + src[start:end] + HARNESS, encoding="utf-8")
            build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    str(source), "-o", str(binary)],
                                   text=True, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

if __name__ == "__main__":
    unittest.main()
