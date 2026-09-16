rule rule_mimikatz_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikatz"
        rule_category = "signature_keyword"

    strings:
                        $string1_mimikatz_signature_keyword = /Gen\:Variant\.Mimikatz/ nocase ascii wide
                        $string2_mimikatz_signature_keyword = /HackTool\.Mimikatz/ nocase ascii wide
                        $string3_mimikatz_signature_keyword = "HackTool/Mimikatz" nocase ascii wide
                        $string4_mimikatz_signature_keyword = "HackTool:Win32/Mimilove" nocase ascii wide
                        $string5_mimikatz_signature_keyword = /HEUR\:Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
                        $string6_mimikatz_signature_keyword = "HKTL_MIMIKATZ" nocase ascii wide
                        $string7_mimikatz_signature_keyword = /Mimikatz\.Spyware\.Stealer\.DDS/ nocase ascii wide
                        $string8_mimikatz_signature_keyword = /Trojan\/Win\.Mimikatz/ nocase ascii wide
                        $string9_mimikatz_signature_keyword = /Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
                        $string10_mimikatz_signature_keyword = /Win32\.Mimikatz/ nocase ascii wide
                        $string11_mimikatz_signature_keyword = /Win32\/Riskware\.Mimikatz/ nocase ascii wide
                        $string12_mimikatz_signature_keyword = /Win64\.Mimikatz/ nocase ascii wide
                        $string13_mimikatz_signature_keyword = "Win64/Riskware Mimikatz" nocase ascii wide
                        $string14_mimikatz_signature_keyword = /Win64\/Riskware\.Mimikatz/ nocase ascii wide
                        $string15_mimikatz_signature_keyword = /Win64\/Riskware\.Mimikatz/ nocase ascii wide

    condition:
        any of them
}