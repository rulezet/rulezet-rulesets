rule rule_BadPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BadPotato_offensive_tool_keyword = /\/BadPotato\.exe/ nocase ascii wide
                        $string2_BadPotato_offensive_tool_keyword = /\/BadPotato\.git/ nocase ascii wide
                        $string3_BadPotato_offensive_tool_keyword = /\\BadPotato\.csproj/ nocase ascii wide
                        $string4_BadPotato_offensive_tool_keyword = /\\BadPotato\.exe/ nocase ascii wide
                        $string5_BadPotato_offensive_tool_keyword = /\<BadPotato\.exe\>/ nocase ascii wide
                        $string6_BadPotato_offensive_tool_keyword = ">BadPotato<" nocase ascii wide
                        $string7_BadPotato_offensive_tool_keyword = "0527a14f-1591-4d94-943e-d6d784a50549" nocase ascii wide
                        $string8_BadPotato_offensive_tool_keyword = "063bc732edb5ca68d2122d0311ddb46dd38ff05074945566d1fa067c3579d767" nocase ascii wide
                        $string9_BadPotato_offensive_tool_keyword = /BadPotato\-master\.zip/ nocase ascii wide
                        $string10_BadPotato_offensive_tool_keyword = "BeichenDream/BadPotato" nocase ascii wide

    condition:
        any of them
}