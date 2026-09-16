rule rule_DeadPotato_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'DeadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeadPotato"
        rule_category = "signature_keyword"

    strings:
                        $string1_DeadPotato_signature_keyword = "Trojan:MSIL/GodPotato" nocase ascii wide

    condition:
        any of them
}