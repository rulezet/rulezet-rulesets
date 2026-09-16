rule OffensiveCSharp
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCSharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/OffensiveCSharp\.git/ nocase ascii wide
                        $string2 = "/OffensiveCSharp/" nocase ascii wide
                        $string3 = /\\OffensiveCSharp\\/ nocase ascii wide
                        $string4 = "OffensiveCSharp-master" nocase ascii wide

    condition:
        any of them
}