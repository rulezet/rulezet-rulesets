rule rule_xz_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'xz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xz"
        rule_category = "signature_keyword"

    strings:
                        $string1_xz_signature_keyword = /HEUR\:Trojan\.Script\.XZ/ nocase ascii wide
                        $string2_xz_signature_keyword = /MEM\:Trojan\.Linux\.XZ/
                        $string3_xz_signature_keyword = /Trojan\.Shell\.XZ/ nocase ascii wide

    condition:
        any of them
}