rule rule_adfind_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "signature_keyword"

    strings:
                        $string1_adfind_signature_keyword = /AdFind\s\(PUA\)/ nocase ascii wide
                        $string2_adfind_signature_keyword = "HackTool:Win32/AdFind" nocase ascii wide
                        $string3_adfind_signature_keyword = /RiskWare\.AdFind/ nocase ascii wide
                        $string4_adfind_signature_keyword = "Riskware/AdFind" nocase ascii wide
                        $string5_adfind_signature_keyword = /Trojan\:Win32\/RemoteSysDisc\.E\!adfind/ nocase ascii wide

    condition:
        any of them
}