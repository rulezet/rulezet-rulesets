rule rule_DEDSEC_RANSOMWARE_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'DEDSEC-RANSOMWARE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DEDSEC-RANSOMWARE"
        rule_category = "signature_keyword"

    strings:
                        $string1_DEDSEC_RANSOMWARE_signature_keyword = "Ransom:Win32/Dedsec" nocase ascii wide

    condition:
        any of them
}