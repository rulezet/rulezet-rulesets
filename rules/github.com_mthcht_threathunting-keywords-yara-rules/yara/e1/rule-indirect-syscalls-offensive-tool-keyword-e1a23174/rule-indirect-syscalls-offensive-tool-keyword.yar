rule rule_Indirect_Syscalls_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Indirect-Syscalls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Indirect-Syscalls"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Indirect_Syscalls_offensive_tool_keyword = /CT_Indirect_Syscalls\.c/ nocase ascii wide
                        $string2_Indirect_Syscalls_offensive_tool_keyword = /CT_Indirect_Syscalls\.exe/ nocase ascii wide
                        $string3_Indirect_Syscalls_offensive_tool_keyword = /CT_Indirect_Syscalls\.sln/ nocase ascii wide
                        $string4_Indirect_Syscalls_offensive_tool_keyword = /CT_Indirect_Syscalls\.vcxproj/ nocase ascii wide
                        $string5_Indirect_Syscalls_offensive_tool_keyword = /Direct\-Syscalls\-vs\-Indirect\-Syscalls\.git/ nocase ascii wide

    condition:
        any of them
}