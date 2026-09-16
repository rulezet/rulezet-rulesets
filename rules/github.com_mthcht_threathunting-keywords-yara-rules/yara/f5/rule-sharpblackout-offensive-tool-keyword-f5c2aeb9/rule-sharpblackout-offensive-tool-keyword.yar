rule rule_SharpBlackout_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpBlackout' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlackout"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpBlackout_offensive_tool_keyword = /\/SharpBlackout\.git/ nocase ascii wide
                        $string2_SharpBlackout_offensive_tool_keyword = "07DFC5AA-5B1F-4CCC-A3D3-816ECCBB6CB6" nocase ascii wide
                        $string3_SharpBlackout_offensive_tool_keyword = "dmcxblue/SharpBlackout" nocase ascii wide
                        $string4_SharpBlackout_offensive_tool_keyword = /SharpBlackout.{0,1000}\s\-p\s/ nocase ascii wide
                        $string5_SharpBlackout_offensive_tool_keyword = /SharpBlackOut\.csproj/ nocase ascii wide
                        $string6_SharpBlackout_offensive_tool_keyword = /SharpBlackout\.exe/ nocase ascii wide
                        $string7_SharpBlackout_offensive_tool_keyword = /SharpBlackOut\.pdb/ nocase ascii wide
                        $string8_SharpBlackout_offensive_tool_keyword = /SharpBlackOut\.sln/ nocase ascii wide
                        $string9_SharpBlackout_offensive_tool_keyword = "SharpBlackout-main" nocase ascii wide
                        $string10_SharpBlackout_offensive_tool_keyword = /Terminating\sWindows\sDefender\?/ nocase ascii wide

    condition:
        any of them
}