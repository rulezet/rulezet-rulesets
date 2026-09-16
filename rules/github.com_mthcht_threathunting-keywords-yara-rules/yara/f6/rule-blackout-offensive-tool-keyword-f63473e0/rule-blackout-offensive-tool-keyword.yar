rule rule_Blackout_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Blackout' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Blackout"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Blackout_offensive_tool_keyword = /\sBlackout\.cpp/ nocase ascii wide
                        $string2_Blackout_offensive_tool_keyword = /\sBlackout\.sln/ nocase ascii wide
                        $string3_Blackout_offensive_tool_keyword = /\sBlackout\.sys/ nocase ascii wide
                        $string4_Blackout_offensive_tool_keyword = /\/Blackout\.cpp/ nocase ascii wide
                        $string5_Blackout_offensive_tool_keyword = /\/Blackout\.exe/ nocase ascii wide
                        $string6_Blackout_offensive_tool_keyword = /\/Blackout\.git/ nocase ascii wide
                        $string7_Blackout_offensive_tool_keyword = /\/Blackout\.sln/ nocase ascii wide
                        $string8_Blackout_offensive_tool_keyword = /\/Blackout\.sys/ nocase ascii wide
                        $string9_Blackout_offensive_tool_keyword = /\\Blackout\.cpp/ nocase ascii wide
                        $string10_Blackout_offensive_tool_keyword = /\\Blackout\.exe/ nocase ascii wide
                        $string11_Blackout_offensive_tool_keyword = /\\Blackout\.sln/ nocase ascii wide
                        $string12_Blackout_offensive_tool_keyword = /\\Blackout\.sys/ nocase ascii wide
                        $string13_Blackout_offensive_tool_keyword = /\\Blackout\.vcxproj/ nocase ascii wide
                        $string14_Blackout_offensive_tool_keyword = /Blackout\.exe\s/ nocase ascii wide
                        $string15_Blackout_offensive_tool_keyword = "ZeroMemoryEx/Blackout" nocase ascii wide

    condition:
        any of them
}