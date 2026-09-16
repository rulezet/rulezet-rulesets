rule rule_Lumma_Stealer_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lumma Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lumma Stealer"
        rule_category = "signature_keyword"

    strings:
                        $string1_Lumma_Stealer_signature_keyword = "Trojan:Win64/Lumma" nocase ascii wide

    condition:
        any of them
}