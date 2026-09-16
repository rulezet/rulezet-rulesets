rule dnstwist
{
    meta:
        description = "Detection patterns for the tool 'dnstwist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnstwist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --fuzzers addition" nocase ascii wide
                        $string2 = " --fuzzers bitsquatting" nocase ascii wide
                        $string3 = " --fuzzers cyrillic" nocase ascii wide
                        $string4 = " --fuzzers dictionary" nocase ascii wide
                        $string5 = " --fuzzers homoglyph" nocase ascii wide
                        $string6 = " --fuzzers hyphenation" nocase ascii wide
                        $string7 = " --fuzzers insertion" nocase ascii wide
                        $string8 = " --fuzzers omission" nocase ascii wide
                        $string9 = " --fuzzers repetition" nocase ascii wide
                        $string10 = " --fuzzers replacement" nocase ascii wide
                        $string11 = " --fuzzers subdomain" nocase ascii wide
                        $string12 = " --fuzzers transposition" nocase ascii wide
                        $string13 = " --fuzzers vowel-swap" nocase ascii wide
                        $string14 = "dnstwist" nocase ascii wide
                        $string15 = /Mozilla\/5\.0\s\(.{0,1000}\-bit\)\sdnstwist/ nocase ascii wide
                        $string16 = "randomalice1986@" nocase ascii wide
                        $string17 = "randombob1986@" nocase ascii wide

    condition:
        any of them
}