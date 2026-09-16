rule rule_nltest_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nltest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nltest"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nltest_greyware_tool_keyword = "nltest /all_trusts" nocase ascii wide
                        $string2_nltest_greyware_tool_keyword = "nltest /dclist" nocase ascii wide
                        $string3_nltest_greyware_tool_keyword = "nltest /domain_trusts /v" nocase ascii wide
                        $string4_nltest_greyware_tool_keyword = "nltest /domain_trusts" nocase ascii wide
                        $string5_nltest_greyware_tool_keyword = /nltest\s\/dsgetdc\:.{0,1000}\s\/force/ nocase ascii wide
                        $string6_nltest_greyware_tool_keyword = /nltest\s\/dsgetdc\:.{0,1000}\s\/force/ nocase ascii wide
                        $string7_nltest_greyware_tool_keyword = "nltest /jbc_trusts /all_trusts" nocase ascii wide
                        $string8_nltest_greyware_tool_keyword = "nltest /sc_reset /force" nocase ascii wide
                        $string9_nltest_greyware_tool_keyword = /nltest\s\/server\:.{0,1000}\s\/domain_trusts/ nocase ascii wide
                        $string10_nltest_greyware_tool_keyword = /nltest\s\/server\:.{0,1000}\s\/trusted_domains\s\/v/ nocase ascii wide
                        $string11_nltest_greyware_tool_keyword = "nltest -dsgetdc" nocase ascii wide
                        $string12_nltest_greyware_tool_keyword = /nltest.{0,1000}\/dclist\:/ nocase ascii wide

    condition:
        any of them
}