rule EXOCET_AV_Evasion
{
    meta:
        description = "Detection patterns for the tool 'EXOCET-AV-Evasion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EXOCET-AV-Evasion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sexocet\.go\s.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /\/exocet\.elf/ nocase ascii wide
                        $string3 = /\/exocet\.exe/ nocase ascii wide
                        $string4 = /\/EXOCET\-AV\-Evasion\.git/ nocase ascii wide
                        $string5 = /\\beacon\-in\-go\.exe/ nocase ascii wide
                        $string6 = /\\exocet\.elf/ nocase ascii wide
                        $string7 = /\\exocet\.exe/ nocase ascii wide
                        $string8 = /\\inline\-shellcode\-test\.c/ nocase ascii wide
                        $string9 = "EXOCET-AV-Evasion-master" nocase ascii wide
                        $string10 = /exocet\-shellcode\-exec\-redo\.go/ nocase ascii wide
                        $string11 = /func\sdecryptMalware\(/ nocase ascii wide
                        $string12 = /meterpreter\-in\-go\.exe/ nocase ascii wide
                        $string13 = "Output malware sample selected: " nocase ascii wide
                        $string14 = "tanc7/EXOCET-AV-Evasion" nocase ascii wide
                        $string15 = /The\smalware\sGo\sfile\shas\sbeen\scompleted\./ nocase ascii wide

    condition:
        any of them
}