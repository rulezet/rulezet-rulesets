rule Misc_Suspicious_Strings
{
    meta:
        description = "Miscellaneous malware strings"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "backdoor" nocase ascii wide
        $a1 = "virus" nocase ascii wide fullword
        $a2 = "hack" nocase ascii wide fullword
        $a3 = "exploit" nocase ascii wide
        $a4 = "cmd.exe" nocase ascii wide
        $a5 = "CWSandbox" nocase wide ascii         $a6 = "System32\\drivers\\etc\\hosts" nocase wide ascii
    condition:
        any of them
}