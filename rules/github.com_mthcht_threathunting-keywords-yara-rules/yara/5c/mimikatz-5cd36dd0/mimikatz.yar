rule mimikatz
{
    meta:
        description = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikatz"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Gen\:Variant\.Mimikatz/ nocase ascii wide
                        $string2 = /HackTool\.Mimikatz/ nocase ascii wide
                        $string3 = "HackTool/Mimikatz" nocase ascii wide
                        $string4 = "HackTool:Win32/Mimilove" nocase ascii wide
                        $string5 = /HEUR\:Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
                        $string6 = "HKTL_MIMIKATZ" nocase ascii wide
                        $string7 = /Mimikatz\.Spyware\.Stealer\.DDS/ nocase ascii wide
                        $string8 = /Trojan\/Win\.Mimikatz/ nocase ascii wide
                        $string9 = /Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
                        $string10 = /Win32\.Mimikatz/ nocase ascii wide
                        $string11 = /Win32\/Riskware\.Mimikatz/ nocase ascii wide
                        $string12 = /Win64\.Mimikatz/ nocase ascii wide
                        $string13 = "Win64/Riskware Mimikatz" nocase ascii wide
                        $string14 = /Win64\/Riskware\.Mimikatz/ nocase ascii wide
                        $string15 = /Win64\/Riskware\.Mimikatz/ nocase ascii wide

    condition:
        any of them
}