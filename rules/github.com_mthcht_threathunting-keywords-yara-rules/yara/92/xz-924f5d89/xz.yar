rule xz
{
    meta:
        description = "Detection patterns for the tool 'xz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xz"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HEUR\:Trojan\.Script\.XZ/ nocase ascii wide
                        $string2 = /MEM\:Trojan\.Linux\.XZ/
                        $string3 = /Trojan\.Shell\.XZ/ nocase ascii wide

    condition:
        any of them
}