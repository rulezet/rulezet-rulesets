rule Stardust
{
    meta:
        description = "Detection patterns for the tool 'Stardust' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stardust"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "\"Stardust MessageBox\"" nocase ascii wide
                        $string2 = /\/stardust\.x64\.exe/ nocase ascii wide
                        $string3 = /\/Stardust\/scripts\/loader\.x64\.exe/ nocase ascii wide
                        $string4 = /\/x64\/Stardust\.asm/ nocase ascii wide
                        $string5 = /\[\+\]\sExecute\sshellcode\.\.\.\spress\senter/ nocase ascii wide
                        $string6 = /\\stardust\.x64\.bin/ nocase ascii wide
                        $string7 = /\\stardust\.x64\.exe/ nocase ascii wide
                        $string8 = /\\Stardust\\scripts\\loader\.x64\.exe/ nocase ascii wide
                        $string9 = /\\x64\\Stardust\.asm/ nocase ascii wide
                        $string10 = /bin\/stardust\.x64\.bin/ nocase ascii wide
                        $string11 = /https\:\/\/5pider\.net\/blog\/2024\/01\/27\/modern\-shellcode\-implant\-design/ nocase ascii wide
                        $string12 = /loader\.x64\.exe\.exe/ nocase ascii wide
                        $string13 = /Stardust\.Win32\.NtProtectVirtualMemory\(/ nocase ascii wide
                        $string14 = /Stardust\.Win32\.RtlAllocateHeap\(/ nocase ascii wide
                        $string15 = "STARDUST_MACROS_H" nocase ascii wide

    condition:
        any of them
}