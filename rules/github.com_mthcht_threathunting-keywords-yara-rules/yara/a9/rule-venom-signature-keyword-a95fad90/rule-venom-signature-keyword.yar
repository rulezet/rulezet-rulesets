rule rule_Venom_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Venom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Venom"
        rule_category = "signature_keyword"

    strings:
                        $string1_Venom_signature_keyword = "Trojan:Win32/Casdet!rfn" nocase ascii wide

    condition:
        any of them
}