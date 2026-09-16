rule NTDLLReflection
{
    meta:
        description = "Detection patterns for the tool 'NTDLLReflection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTDLLReflection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " NtCr3at3Thr3adEx @ " nocase ascii wide
                        $string2 = /\/NTDLLReflection\.git/ nocase ascii wide
                        $string3 = "9D365106-D7B8-4B5E-82CC-6D6ABCDCA2B8" nocase ascii wide
                        $string4 = "NTDLLReflection-main" nocase ascii wide
                        $string5 = "NtWa1tF0rS1ngle0bj3ct Executed" nocase ascii wide
                        $string6 = /ReflectiveNTDLL\.cpp/ nocase ascii wide
                        $string7 = /ReflectiveNTDLL\.exe/ nocase ascii wide
                        $string8 = /ReflectiveNTDLL\.sln/ nocase ascii wide
                        $string9 = /ReflectiveNTDLL\.vcxproj/ nocase ascii wide
                        $string10 = "TheD1rkMtr/NTDLLReflection" nocase ascii wide

    condition:
        any of them
}