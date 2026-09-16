rule rule_LOLSpoof_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "signature_keyword"

    strings:
                        $string1_LOLSpoof_signature_keyword = "ATK/LOLSpoof-A" nocase ascii wide

    condition:
        any of them
}