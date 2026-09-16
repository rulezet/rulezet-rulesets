rule SysWhispers3
{
    meta:
        description = "Detection patterns for the tool 'SysWhispers3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SysWhispers3"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-functions\sNtProtectVirtualMemory.{0,1000}NtWriteVirtualMemory\s\-o\ssyscalls_mem/ nocase ascii wide
                        $string2 = " --preset all -o syscalls_all" nocase ascii wide
                        $string3 = " --preset common -o syscalls_common" nocase ascii wide
                        $string4 = "/SysWhispers2" nocase ascii wide
                        $string5 = "/SysWhispers3" nocase ascii wide
                        $string6 = /\/SysWhispers3\.git/ nocase ascii wide
                        $string7 = /syswhispers\.py/ nocase ascii wide

    condition:
        any of them
}