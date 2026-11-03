import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("switchboard", Path(__file__).parents[1] / "bin" / "switchboard.py")
switchboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(switchboard)


class WildcardIngressTests(unittest.TestCase):
    def setUp(self):
        switchboard.cfg = {"shard": "cabin"}

    def test_exact_wildcard_zones_preserve_authority(self):
        for zone in ("dev.chordzy.com", "auth-dev.chordzy.com", "assets-dev.chordzy.com"):
            match = switchboard.re_in_matcher.match("wss!://*!:" + zone + "@chordzy-dev")
            self.assertIsNotNone(match)
            hosts = switchboard._get_fqdns(match)
            self.assertEqual(hosts, ["*." + zone])
            self.assertEqual(switchboard._virtual_host(hosts, [])['domains'], hosts)
            self.assertEqual(match.group('domain'), zone)

    def test_partial_wildcards_refused(self):
        for value in ("foo*", "*foo", "**", "foo.*"):
            self.assertIsNone(switchboard.re_in_matcher.match("https://" + value + ":dev.chordzy.com@gateway"))

    def test_wildcard_cannot_be_sharded_or_optional(self):
        for value in ("*", "*?!"):
            match = switchboard.re_in_matcher.match("https://" + value + ":dev.chordzy.com@gateway")
            with self.assertRaises(ValueError):
                switchboard._get_fqdns(match)

    def test_existing_subdomains_keep_sharding(self):
        match = switchboard.re_in_matcher.match("https://api:chordzy.com@gateway")
        self.assertEqual(switchboard._get_fqdns(match), ["cabin-api.chordzy.com"])


if __name__ == "__main__":
    unittest.main()
