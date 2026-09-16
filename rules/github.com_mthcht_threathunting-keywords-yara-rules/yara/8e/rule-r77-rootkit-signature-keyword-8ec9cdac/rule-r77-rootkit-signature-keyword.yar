rule rule_r77_rootkit_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'r77-rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "r77-rootkit"
        rule_category = "signature_keyword"

    strings:
                        $string1_r77_rootkit_signature_keyword = "Trojan:Win64/r77RootKit" nocase ascii wide

    condition:
        any of them
}