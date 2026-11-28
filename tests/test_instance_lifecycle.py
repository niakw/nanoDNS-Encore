"""Exercise the production instance-lock helper using independent host processes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class InstanceLifecycle(unittest.TestCase):
    def test_lock_rejects_duplicate_and_releases_on_process_exit(self):
        src = (ROOT / "main.c").read_text()
        start = src.index("static int\nacquire_instance_lock(")
        end = src.index("\nstatic int\nensure_default_config_exists(", start)
        helper = src[start:end]
        program = """#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
""" + helper + """
int main(int argc, char **argv) {
    if(argc!=2) return 2;
    int fd=acquire_instance_lock(argv[1]);
    if(fd<0) return 3;
    puts("locked"); fflush(stdout);
    (void)getchar();
    close(fd);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            source=p/"test.c"
            binary=p/"test"
            source.write_text(program)
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(source),"-o",str(binary)],check=True)
            path=str(p/"resident.lock")
            first=subprocess.Popen([str(binary),path],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(first.stdout.readline().strip(),"locked")
                self.assertEqual(subprocess.run([str(binary),path],input="",text=True,capture_output=True).returncode,3)
                first.stdin.close()
                self.assertEqual(first.wait(timeout=5),0)
                self.assertEqual(subprocess.run([str(binary),path],input="",text=True,capture_output=True).returncode,0)
            finally:
                if first.poll() is None:
                    first.kill()
                    first.wait()
                first.stdout.close()
                if not first.stdin.closed: first.stdin.close()

    def test_admission_precedes_side_effects(self):
        src=(ROOT/"main.c").read_text().split("main(void) {",1)[1]
        lock=src.index("acquire_instance_lock(INSTANCE_LOCK_PATH)")
        for token in ("ensure_default_config_exists(CONFIG_PATH)", "logger_init(&cfg)", "net_init()"):
            self.assertLess(lock,src.index(token))
        self.assertIn("if(!g_running) goto shutdown;",src)
        self.assertIn("close(instance_fd);",src)
