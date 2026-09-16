rule rule_holehe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'holehe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "holehe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_holehe_offensive_tool_keyword = " install holehe"
                        $string2_holehe_offensive_tool_keyword = /\/holehe\.git/
                        $string3_holehe_offensive_tool_keyword = /from\sholehe\.core\simport/
                        $string4_holehe_offensive_tool_keyword = /holehe\s.{0,1000}\@gmail\.com/
                        $string5_holehe_offensive_tool_keyword = /holehe\.core\:main/
                        $string6_holehe_offensive_tool_keyword = /holehe\\holehe/
                        $string7_holehe_offensive_tool_keyword = /holehe\-master\./
                        $string8_holehe_offensive_tool_keyword = "megadose/holehe"
                        $string9_holehe_offensive_tool_keyword = /megadose\@protonmail\.com/ nocase ascii wide
                        $string10_holehe_offensive_tool_keyword = /pornhub\.py/

    condition:
        any of them
}