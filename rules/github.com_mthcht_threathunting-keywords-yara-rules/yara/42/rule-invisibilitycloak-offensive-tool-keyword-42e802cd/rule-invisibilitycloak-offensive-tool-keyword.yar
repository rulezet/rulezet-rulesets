rule rule_InvisibilityCloak_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'InvisibilityCloak' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InvisibilityCloak"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_InvisibilityCloak_offensive_tool_keyword = /\s\-d\s.{0,1000}\s\-n\s.{0,1000}\s\-m\sreverse.{0,1000}\=/ nocase ascii wide
                        $string2_InvisibilityCloak_offensive_tool_keyword = /\s\-d\s.{0,1000}\s\-n\s.{0,1000}\s\-m\srot13/ nocase ascii wide
                        $string3_InvisibilityCloak_offensive_tool_keyword = /\s\-n\s.{0,1000}TotallyLegitTool/ nocase ascii wide
                        $string4_InvisibilityCloak_offensive_tool_keyword = /InvisibilityCloak\.py/ nocase ascii wide

    condition:
        any of them
}