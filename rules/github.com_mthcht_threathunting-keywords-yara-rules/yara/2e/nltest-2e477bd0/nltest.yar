rule nltest
{
    meta:
        description = "Detection patterns for the tool 'nltest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nltest"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "nltest /all_trusts" nocase ascii wide
                        $string2 = "nltest /dclist" nocase ascii wide
                        $string3 = "nltest /domain_trusts /v" nocase ascii wide
                        $string4 = "nltest /domain_trusts" nocase ascii wide
                        $string5 = /nltest\s\/dsgetdc\:.{0,1000}\s\/force/ nocase ascii wide
                        $string6 = /nltest\s\/dsgetdc\:.{0,1000}\s\/force/ nocase ascii wide
                        $string7 = "nltest /jbc_trusts /all_trusts" nocase ascii wide
                        $string8 = "nltest /sc_reset /force" nocase ascii wide
                        $string9 = /nltest\s\/server\:.{0,1000}\s\/domain_trusts/ nocase ascii wide
                        $string10 = /nltest\s\/server\:.{0,1000}\s\/trusted_domains\s\/v/ nocase ascii wide
                        $string11 = "nltest -dsgetdc" nocase ascii wide
                        $string12 = /nltest.{0,1000}\/dclist\:/ nocase ascii wide

    condition:
        any of them
}