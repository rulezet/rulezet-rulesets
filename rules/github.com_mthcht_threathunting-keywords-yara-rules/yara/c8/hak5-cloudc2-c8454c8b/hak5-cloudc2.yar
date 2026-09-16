rule hak5_cloudc2
{
    meta:
        description = "Detection patterns for the tool 'hak5 cloudc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hak5 cloudc2"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Hacktool\.Hakc2/ nocase ascii wide
                        $string2 = /Hacktool\.ZIP\.HakC2/ nocase ascii wide
                        $string3 = /Riskware\.Hakc2/ nocase ascii wide
                        $string4 = "Riskware/Hakc2" nocase ascii wide
                        $string5 = /Trojan\/Win32\.Hakc2/ nocase ascii wide

    condition:
        any of them
}