rule rule_dialupass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dialupass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dialupass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dialupass_offensive_tool_keyword = /\\Dialupass\.cfg/ nocase ascii wide
                        $string2_dialupass_offensive_tool_keyword = "1e3ec12fbe9825c1eb044994d27c6fb97e5b2cee352d114b0ae6f8862e2a2dd5" nocase ascii wide
                        $string3_dialupass_offensive_tool_keyword = "598555a7e053c7456ee8a06a892309386e69d473c73284de9bbc0ba73b17e70a" nocase ascii wide
                        $string4_dialupass_offensive_tool_keyword = "Dialup/VPN Password Recovery" nocase ascii wide
                        $string5_dialupass_offensive_tool_keyword = "Dialup/VPN Passwords List" nocase ascii wide
                        $string6_dialupass_offensive_tool_keyword = /Dialupass\.exe/ nocase ascii wide
                        $string7_dialupass_offensive_tool_keyword = /Dialupass\.zip/ nocase ascii wide

    condition:
        any of them
}