rule rule_ghostsocks_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'ghostsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghostsocks"
        rule_category = "signature_keyword"

    strings:
                        $string1_ghostsocks_signature_keyword = "Trojan:Win32/GhostSocks" nocase ascii wide

    condition:
        any of them
}