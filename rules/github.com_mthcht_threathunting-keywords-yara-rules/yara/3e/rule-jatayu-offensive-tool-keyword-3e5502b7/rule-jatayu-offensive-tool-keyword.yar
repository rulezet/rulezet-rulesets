rule rule_Jatayu_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Jatayu' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jatayu"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Jatayu_offensive_tool_keyword = "/SpiderMate/Jatayu" nocase ascii wide
                        $string2_Jatayu_offensive_tool_keyword = "bb3b1a1f-0447-42a6-955a-88681fb88499" nocase ascii wide
                        $string3_Jatayu_offensive_tool_keyword = /jatayu\.php/ nocase ascii wide
                        $string4_Jatayu_offensive_tool_keyword = /jatayu\-image\.png/ nocase ascii wide

    condition:
        any of them
}