rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /AdFind\s\(PUA\)/ nocase ascii wide
                        $string2 = "HackTool:Win32/AdFind" nocase ascii wide
                        $string3 = /RiskWare\.AdFind/ nocase ascii wide
                        $string4 = "Riskware/AdFind" nocase ascii wide
                        $string5 = /Trojan\:Win32\/RemoteSysDisc\.E\!adfind/ nocase ascii wide

    condition:
        any of them
}