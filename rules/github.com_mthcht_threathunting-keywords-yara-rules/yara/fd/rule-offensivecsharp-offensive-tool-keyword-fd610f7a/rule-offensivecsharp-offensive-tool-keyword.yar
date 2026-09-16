rule rule_OffensiveCSharp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCSharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OffensiveCSharp_offensive_tool_keyword = /\/OffensiveCSharp\.git/ nocase ascii wide
                        $string2_OffensiveCSharp_offensive_tool_keyword = "/OffensiveCSharp/" nocase ascii wide
                        $string3_OffensiveCSharp_offensive_tool_keyword = /\\OffensiveCSharp\\/ nocase ascii wide
                        $string4_OffensiveCSharp_offensive_tool_keyword = "OffensiveCSharp-master" nocase ascii wide

    condition:
        any of them
}