rule rule_arp_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'arp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arp"
        rule_category = "signature_keyword"

    strings:
                        $string1_arp_signature_keyword = /cmd\.exe\s\/c\sarp\s\-a\s\>\sC\:\\windows\\.{0,1000}\.out\s2\>\&1/ nocase ascii wide

    condition:
        any of them
}