rule rule_Stardust_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Stardust' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stardust"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Stardust_offensive_tool_keyword = "\"Stardust MessageBox\"" nocase ascii wide
                        $string2_Stardust_offensive_tool_keyword = /\/stardust\.x64\.exe/ nocase ascii wide
                        $string3_Stardust_offensive_tool_keyword = /\/Stardust\/scripts\/loader\.x64\.exe/ nocase ascii wide
                        $string4_Stardust_offensive_tool_keyword = /\/x64\/Stardust\.asm/ nocase ascii wide
                        $string5_Stardust_offensive_tool_keyword = /\[\+\]\sExecute\sshellcode\.\.\.\spress\senter/ nocase ascii wide
                        $string6_Stardust_offensive_tool_keyword = /\\stardust\.x64\.bin/ nocase ascii wide
                        $string7_Stardust_offensive_tool_keyword = /\\stardust\.x64\.exe/ nocase ascii wide
                        $string8_Stardust_offensive_tool_keyword = /\\Stardust\\scripts\\loader\.x64\.exe/ nocase ascii wide
                        $string9_Stardust_offensive_tool_keyword = /\\x64\\Stardust\.asm/ nocase ascii wide
                        $string10_Stardust_offensive_tool_keyword = /bin\/stardust\.x64\.bin/ nocase ascii wide
                        $string11_Stardust_offensive_tool_keyword = /https\:\/\/5pider\.net\/blog\/2024\/01\/27\/modern\-shellcode\-implant\-design/ nocase ascii wide
                        $string12_Stardust_offensive_tool_keyword = /loader\.x64\.exe\.exe/ nocase ascii wide
                        $string13_Stardust_offensive_tool_keyword = /Stardust\.Win32\.NtProtectVirtualMemory\(/ nocase ascii wide
                        $string14_Stardust_offensive_tool_keyword = /Stardust\.Win32\.RtlAllocateHeap\(/ nocase ascii wide
                        $string15_Stardust_offensive_tool_keyword = "STARDUST_MACROS_H" nocase ascii wide

    condition:
        any of them
}