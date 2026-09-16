rule rule_merlin_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'merlin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin"
        rule_category = "signature_keyword"

    strings:
                        $string1_merlin_signature_keyword = "Trojan:Win32/TrickbotCrypt" nocase ascii wide

    condition:
        any of them
}