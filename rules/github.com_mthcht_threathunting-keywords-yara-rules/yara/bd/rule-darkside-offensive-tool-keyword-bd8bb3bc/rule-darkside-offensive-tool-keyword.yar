rule rule_Darkside_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Darkside' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Darkside"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Darkside_offensive_tool_keyword = /\/Darkside\.exe/ nocase ascii wide
                        $string2_Darkside_offensive_tool_keyword = /\/Darkside\.git/ nocase ascii wide
                        $string3_Darkside_offensive_tool_keyword = /\/Darkside\.sln/ nocase ascii wide
                        $string4_Darkside_offensive_tool_keyword = /\\Darkside\.exe/ nocase ascii wide
                        $string5_Darkside_offensive_tool_keyword = /\\Darkside\.sln/ nocase ascii wide
                        $string6_Darkside_offensive_tool_keyword = "D90EFC93-2F8B-4427-B967-0E78ED45611E" nocase ascii wide
                        $string7_Darkside_offensive_tool_keyword = /Darkside\.exe\s\-p/ nocase ascii wide
                        $string8_Darkside_offensive_tool_keyword = /Darkside\-master\.zip/ nocase ascii wide
                        $string9_Darkside_offensive_tool_keyword = "ph4nt0mbyt3/Darkside" nocase ascii wide

    condition:
        any of them
}