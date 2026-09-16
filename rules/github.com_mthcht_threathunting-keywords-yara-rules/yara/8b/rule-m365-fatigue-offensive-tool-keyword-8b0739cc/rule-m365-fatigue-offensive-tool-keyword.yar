rule rule_m365_fatigue_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'm365-fatigue' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "m365-fatigue"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_m365_fatigue_offensive_tool_keyword = /\sm365\-fatigue\.py\s/ nocase ascii wide
                        $string2_m365_fatigue_offensive_tool_keyword = /\/m365\-fatigue\.git/ nocase ascii wide
                        $string3_m365_fatigue_offensive_tool_keyword = /\/m365\-fatigue\.py/ nocase ascii wide
                        $string4_m365_fatigue_offensive_tool_keyword = /\\m365\-fatigue\.py/ nocase ascii wide
                        $string5_m365_fatigue_offensive_tool_keyword = "0xB455/m365-fatigue" nocase ascii wide
                        $string6_m365_fatigue_offensive_tool_keyword = "d86bebcde6d5835cd2237d4e37df9858102002a4b9211aa3827e4bec0eca9897" nocase ascii wide

    condition:
        any of them
}