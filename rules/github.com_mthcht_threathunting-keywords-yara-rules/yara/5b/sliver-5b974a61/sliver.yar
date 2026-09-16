rule sliver
{
    meta:
        description = "Detection patterns for the tool 'sliver' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sliver"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.Win32\.Sliver/ nocase ascii wide
                        $string2 = /HEUR\:Trojan\.Linux\.Vilers\.a/ nocase ascii wide
                        $string3 = /Multi\.Trojan\.Sliver/ nocase ascii wide
                        $string4 = /Unix\.Malware\.Sliver\-/ nocase ascii wide
                        $string5 = "VirTool:Linux/Sliver" nocase ascii wide

    condition:
        any of them
}