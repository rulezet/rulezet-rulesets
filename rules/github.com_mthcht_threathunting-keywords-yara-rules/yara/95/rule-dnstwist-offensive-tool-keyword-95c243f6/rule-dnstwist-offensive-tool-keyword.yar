rule rule_dnstwist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnstwist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnstwist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnstwist_offensive_tool_keyword = " --fuzzers addition" nocase ascii wide
                        $string2_dnstwist_offensive_tool_keyword = " --fuzzers bitsquatting" nocase ascii wide
                        $string3_dnstwist_offensive_tool_keyword = " --fuzzers cyrillic" nocase ascii wide
                        $string4_dnstwist_offensive_tool_keyword = " --fuzzers dictionary" nocase ascii wide
                        $string5_dnstwist_offensive_tool_keyword = " --fuzzers homoglyph" nocase ascii wide
                        $string6_dnstwist_offensive_tool_keyword = " --fuzzers hyphenation" nocase ascii wide
                        $string7_dnstwist_offensive_tool_keyword = " --fuzzers insertion" nocase ascii wide
                        $string8_dnstwist_offensive_tool_keyword = " --fuzzers omission" nocase ascii wide
                        $string9_dnstwist_offensive_tool_keyword = " --fuzzers repetition" nocase ascii wide
                        $string10_dnstwist_offensive_tool_keyword = " --fuzzers replacement" nocase ascii wide
                        $string11_dnstwist_offensive_tool_keyword = " --fuzzers subdomain" nocase ascii wide
                        $string12_dnstwist_offensive_tool_keyword = " --fuzzers transposition" nocase ascii wide
                        $string13_dnstwist_offensive_tool_keyword = " --fuzzers vowel-swap" nocase ascii wide
                        $string14_dnstwist_offensive_tool_keyword = "dnstwist" nocase ascii wide
                        $string15_dnstwist_offensive_tool_keyword = /Mozilla\/5\.0\s\(.{0,1000}\-bit\)\sdnstwist/ nocase ascii wide
                        $string16_dnstwist_offensive_tool_keyword = "randomalice1986@" nocase ascii wide
                        $string17_dnstwist_offensive_tool_keyword = "randombob1986@" nocase ascii wide

    condition:
        any of them
}