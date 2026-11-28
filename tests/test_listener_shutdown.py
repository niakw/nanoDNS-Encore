from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ListenerShutdown(unittest.TestCase):
    def test_stop_checks_and_debug_only_startup_inventory(self):
        s=(ROOT/"main.c").read_text().split("main(void) {",1)[1]
        self.assertIn("poll(pfds, poll_count, 100)",s)
        self.assertIn("if(!g_running) break;",s)
        self.assertIn("SERVER_LISTENER_COUNT && g_running",s)
        self.assertIn("cfg.rule_count && g_running",s)
        self.assertIn("if(cfg.debug_enabled)",s)
        self.assertNotIn("sleep(1);",s)
