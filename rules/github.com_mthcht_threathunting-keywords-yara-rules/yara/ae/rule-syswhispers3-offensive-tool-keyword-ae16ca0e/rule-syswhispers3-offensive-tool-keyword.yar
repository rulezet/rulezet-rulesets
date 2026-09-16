rule rule_SysWhispers3_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SysWhispers3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SysWhispers3"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SysWhispers3_offensive_tool_keyword = /\s\-\-functions\sNtProtectVirtualMemory.{0,1000}NtWriteVirtualMemory\s\-o\ssyscalls_mem/ nocase ascii wide
                        $string2_SysWhispers3_offensive_tool_keyword = " --preset all -o syscalls_all" nocase ascii wide
                        $string3_SysWhispers3_offensive_tool_keyword = " --preset common -o syscalls_common" nocase ascii wide
                        $string4_SysWhispers3_offensive_tool_keyword = "/SysWhispers2" nocase ascii wide
                        $string5_SysWhispers3_offensive_tool_keyword = "/SysWhispers3" nocase ascii wide
                        $string6_SysWhispers3_offensive_tool_keyword = /\/SysWhispers3\.git/ nocase ascii wide
                        $string7_SysWhispers3_offensive_tool_keyword = /syswhispers\.py/ nocase ascii wide

    condition:
        any of them
}