rule Krueger
{
    meta:
        description = "Detection patterns for the tool 'Krueger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Krueger"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Trojan\.KillAV/ nocase ascii wide

    condition:
        any of them
}