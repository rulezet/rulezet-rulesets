rule rule_Jasmin_Ransomware_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Jasmin-Ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jasmin-Ransomware"
        rule_category = "signature_keyword"

    strings:
                        $string1_Jasmin_Ransomware_signature_keyword = /Ransom\:MSIL\/Jasmin\./ nocase ascii wide

    condition:
        any of them
}