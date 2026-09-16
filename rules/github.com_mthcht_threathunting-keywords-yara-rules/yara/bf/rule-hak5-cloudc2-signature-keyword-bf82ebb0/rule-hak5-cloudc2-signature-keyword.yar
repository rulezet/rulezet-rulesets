rule rule_hak5_cloudc2_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'hak5 cloudc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hak5 cloudc2"
        rule_category = "signature_keyword"

    strings:
                        $string1_hak5_cloudc2_signature_keyword = /Hacktool\.Hakc2/ nocase ascii wide
                        $string2_hak5_cloudc2_signature_keyword = /Hacktool\.ZIP\.HakC2/ nocase ascii wide
                        $string3_hak5_cloudc2_signature_keyword = /Riskware\.Hakc2/ nocase ascii wide
                        $string4_hak5_cloudc2_signature_keyword = "Riskware/Hakc2" nocase ascii wide
                        $string5_hak5_cloudc2_signature_keyword = /Trojan\/Win32\.Hakc2/ nocase ascii wide

    condition:
        any of them
}