rule rule_hping_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hping"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hping_offensive_tool_keyword = " hping3 " nocase ascii wide
                        $string2_hping_offensive_tool_keyword = /\.\/hping\s/
                        $string3_hping_offensive_tool_keyword = "antirez/hping" nocase ascii wide
                        $string4_hping_offensive_tool_keyword = /hping2\.h/ nocase ascii wide
                        $string5_hping_offensive_tool_keyword = "hping3 -" nocase ascii wide
                        $string6_hping_offensive_tool_keyword = "install hping3" nocase ascii wide

    condition:
        any of them
}