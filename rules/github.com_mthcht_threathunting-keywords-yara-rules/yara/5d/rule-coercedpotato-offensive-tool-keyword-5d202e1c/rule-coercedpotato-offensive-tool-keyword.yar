rule rule_CoercedPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CoercedPotato_offensive_tool_keyword = /\/CoercedPotato\.git/ nocase ascii wide
                        $string2_CoercedPotato_offensive_tool_keyword = /\[\+\]\sRUNNING\sALL\sKNOWN\sEXPLOITS/ nocase ascii wide
                        $string3_CoercedPotato_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\spoolss/ nocase ascii wide
                        $string4_CoercedPotato_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\srvsvc/ nocase ascii wide
                        $string5_CoercedPotato_offensive_tool_keyword = /127\.0\.0\.1\/pipe\/coerced\\\\C\$/ nocase ascii wide
                        $string6_CoercedPotato_offensive_tool_keyword = "337ED7BE-969A-40C4-A356-BE99561F4633" nocase ascii wide
                        $string7_CoercedPotato_offensive_tool_keyword = /CoercedPotato\.cpp/ nocase ascii wide
                        $string8_CoercedPotato_offensive_tool_keyword = /CoercedPotato\.exe/ nocase ascii wide
                        $string9_CoercedPotato_offensive_tool_keyword = /CoercedPotato\.sln/ nocase ascii wide
                        $string10_CoercedPotato_offensive_tool_keyword = "CoercedPotato-master" nocase ascii wide
                        $string11_CoercedPotato_offensive_tool_keyword = "Prepouce/CoercedPotato" nocase ascii wide

    condition:
        any of them
}