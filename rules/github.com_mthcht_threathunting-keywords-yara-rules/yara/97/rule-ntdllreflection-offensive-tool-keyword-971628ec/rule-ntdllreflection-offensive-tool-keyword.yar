rule rule_NTDLLReflection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NTDLLReflection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTDLLReflection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NTDLLReflection_offensive_tool_keyword = " NtCr3at3Thr3adEx @ " nocase ascii wide
                        $string2_NTDLLReflection_offensive_tool_keyword = /\/NTDLLReflection\.git/ nocase ascii wide
                        $string3_NTDLLReflection_offensive_tool_keyword = "9D365106-D7B8-4B5E-82CC-6D6ABCDCA2B8" nocase ascii wide
                        $string4_NTDLLReflection_offensive_tool_keyword = "NTDLLReflection-main" nocase ascii wide
                        $string5_NTDLLReflection_offensive_tool_keyword = "NtWa1tF0rS1ngle0bj3ct Executed" nocase ascii wide
                        $string6_NTDLLReflection_offensive_tool_keyword = /ReflectiveNTDLL\.cpp/ nocase ascii wide
                        $string7_NTDLLReflection_offensive_tool_keyword = /ReflectiveNTDLL\.exe/ nocase ascii wide
                        $string8_NTDLLReflection_offensive_tool_keyword = /ReflectiveNTDLL\.sln/ nocase ascii wide
                        $string9_NTDLLReflection_offensive_tool_keyword = /ReflectiveNTDLL\.vcxproj/ nocase ascii wide
                        $string10_NTDLLReflection_offensive_tool_keyword = "TheD1rkMtr/NTDLLReflection" nocase ascii wide

    condition:
        any of them
}