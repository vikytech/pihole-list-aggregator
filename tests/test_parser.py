import unittest

from scripts.build_blocklist import parse_pihole_compatible, valid_abp_blocking_rule


class ParserTests(unittest.TestCase):
    def test_hosts_plain_and_abp(self):
        text = """
! comment
[Adblock Plus 2.0]
0.0.0.0 ads.example.com tracker.example.net
plain.example.org
||wild.example^
@@||allowed.example^
||option.example^$important
example.com##.advert
/path/banner.js
"""
        exact, abp, exact_seen, abp_seen, ignored = parse_pihole_compatible(text)

        self.assertEqual(
            exact,
            {"ads.example.com", "tracker.example.net", "plain.example.org"},
        )
        self.assertEqual(abp, {"||wild.example^"})
        self.assertEqual(exact_seen, 3)
        self.assertEqual(abp_seen, 1)
        self.assertGreaterEqual(ignored, 3)

    def test_duplicate_entries_are_removed(self):
        text = """
dup.example
dup.example
0.0.0.0 dup.example
||dup-parent.example^
||dup-parent.example^
"""
        exact, abp, *_ = parse_pihole_compatible(text)
        self.assertEqual(exact, {"dup.example"})
        self.assertEqual(abp, {"||dup-parent.example^"})

    def test_supported_abp_shape_is_exact(self):
        self.assertTrue(valid_abp_blocking_rule("||example.com^"))
        self.assertFalse(valid_abp_blocking_rule("@@||example.com^"))
        self.assertFalse(valid_abp_blocking_rule("||example.com^$important"))
        self.assertFalse(valid_abp_blocking_rule("||example.com/path^"))


if __name__ == "__main__":
    unittest.main()
