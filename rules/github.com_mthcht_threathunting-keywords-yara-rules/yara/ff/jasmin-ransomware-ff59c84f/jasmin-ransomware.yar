rule Jasmin_Ransomware
{
    meta:
        description = "Detection patterns for the tool 'Jasmin-Ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jasmin-Ransomware"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Ransom\:MSIL\/Jasmin\./ nocase ascii wide

    condition:
        any of them
}