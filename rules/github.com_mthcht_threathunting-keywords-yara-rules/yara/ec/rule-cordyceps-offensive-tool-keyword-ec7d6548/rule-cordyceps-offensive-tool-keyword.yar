rule rule_Cordyceps_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cordyceps' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cordyceps"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cordyceps_offensive_tool_keyword = /\/Cordyceps\.git/ nocase ascii wide
                        $string2_Cordyceps_offensive_tool_keyword = /cordyceps\.exe/ nocase ascii wide
                        $string3_Cordyceps_offensive_tool_keyword = /Cordyceps\-main\.zip/ nocase ascii wide
                        $string4_Cordyceps_offensive_tool_keyword = /nasm\s\-f\swin64\s\.\/syscalls\.asm\s\-o\s\.\/syscalls\.obj/
                        $string5_Cordyceps_offensive_tool_keyword = "pard0p/Cordyceps" nocase ascii wide

    condition:
        any of them
}