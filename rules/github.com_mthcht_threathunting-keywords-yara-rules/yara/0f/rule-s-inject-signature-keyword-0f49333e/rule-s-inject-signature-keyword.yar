rule rule_S_inject_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'S-inject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S-inject"
        rule_category = "signature_keyword"

    strings:
                        $string1_S_inject_signature_keyword = "Trojan:Win64/CobaltStrike" nocase ascii wide

    condition:
        any of them
}