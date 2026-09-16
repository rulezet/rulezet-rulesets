rule Direct_Syscalls
{
    meta:
        description = "Detection patterns for the tool 'Direct-Syscalls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Direct-Syscalls"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /Direct_Syscalls_Create_Thread\.c/ nocase ascii wide
                        $string2 = /Direct_Syscalls_Create_Thread\.exe/ nocase ascii wide
                        $string3 = /Direct_Syscalls_Create_Thread\.sln/ nocase ascii wide
                        $string4 = /Direct_Syscalls_Create_Thread\.vcxproj/ nocase ascii wide

    condition:
        any of them
}