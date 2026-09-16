rule rule_EXOCET_AV_Evasion_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EXOCET-AV-Evasion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EXOCET-AV-Evasion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EXOCET_AV_Evasion_offensive_tool_keyword = /\sexocet\.go\s.{0,1000}\.exe/ nocase ascii wide
                        $string2_EXOCET_AV_Evasion_offensive_tool_keyword = /\/exocet\.elf/ nocase ascii wide
                        $string3_EXOCET_AV_Evasion_offensive_tool_keyword = /\/exocet\.exe/ nocase ascii wide
                        $string4_EXOCET_AV_Evasion_offensive_tool_keyword = /\/EXOCET\-AV\-Evasion\.git/ nocase ascii wide
                        $string5_EXOCET_AV_Evasion_offensive_tool_keyword = /\\beacon\-in\-go\.exe/ nocase ascii wide
                        $string6_EXOCET_AV_Evasion_offensive_tool_keyword = /\\exocet\.elf/ nocase ascii wide
                        $string7_EXOCET_AV_Evasion_offensive_tool_keyword = /\\exocet\.exe/ nocase ascii wide
                        $string8_EXOCET_AV_Evasion_offensive_tool_keyword = /\\inline\-shellcode\-test\.c/ nocase ascii wide
                        $string9_EXOCET_AV_Evasion_offensive_tool_keyword = "EXOCET-AV-Evasion-master" nocase ascii wide
                        $string10_EXOCET_AV_Evasion_offensive_tool_keyword = /exocet\-shellcode\-exec\-redo\.go/ nocase ascii wide
                        $string11_EXOCET_AV_Evasion_offensive_tool_keyword = /func\sdecryptMalware\(/ nocase ascii wide
                        $string12_EXOCET_AV_Evasion_offensive_tool_keyword = /meterpreter\-in\-go\.exe/ nocase ascii wide
                        $string13_EXOCET_AV_Evasion_offensive_tool_keyword = "Output malware sample selected: " nocase ascii wide
                        $string14_EXOCET_AV_Evasion_offensive_tool_keyword = "tanc7/EXOCET-AV-Evasion" nocase ascii wide
                        $string15_EXOCET_AV_Evasion_offensive_tool_keyword = /The\smalware\sGo\sfile\shas\sbeen\scompleted\./ nocase ascii wide

    condition:
        any of them
}