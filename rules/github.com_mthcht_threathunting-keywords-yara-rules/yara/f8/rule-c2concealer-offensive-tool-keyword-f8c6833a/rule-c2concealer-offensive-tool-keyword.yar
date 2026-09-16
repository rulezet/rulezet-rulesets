rule rule_C2concealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2concealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2concealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2concealer_offensive_tool_keyword = " -t C2concealer " nocase ascii wide
                        $string2_C2concealer_offensive_tool_keyword = "/C2concealer" nocase ascii wide
                        $string3_C2concealer_offensive_tool_keyword = "/cobaltstrike/c2lint"
                        $string4_C2concealer_offensive_tool_keyword = "/usr/share/cobaltstrike/"
                        $string5_C2concealer_offensive_tool_keyword = /\\C2concealer/ nocase ascii wide
                        $string6_C2concealer_offensive_tool_keyword = "C2concealer -" nocase ascii wide
                        $string7_C2concealer_offensive_tool_keyword = "C2concealer-master" nocase ascii wide
                        $string8_C2concealer_offensive_tool_keyword = /malleable\-c2\-randomizer\.py/ nocase ascii wide

    condition:
        any of them
}