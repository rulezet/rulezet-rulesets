rule rule_sliver_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'sliver' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sliver"
        rule_category = "signature_keyword"

    strings:
                        $string1_sliver_signature_keyword = /HackTool\.Win32\.Sliver/ nocase ascii wide
                        $string2_sliver_signature_keyword = /HEUR\:Trojan\.Linux\.Vilers\.a/ nocase ascii wide
                        $string3_sliver_signature_keyword = /Multi\.Trojan\.Sliver/ nocase ascii wide
                        $string4_sliver_signature_keyword = /Unix\.Malware\.Sliver\-/ nocase ascii wide
                        $string5_sliver_signature_keyword = "VirTool:Linux/Sliver" nocase ascii wide

    condition:
        any of them
}