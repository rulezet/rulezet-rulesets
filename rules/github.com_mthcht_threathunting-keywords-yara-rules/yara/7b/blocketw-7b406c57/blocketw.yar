rule BlockEtw
{
    meta:
        description = "Detection patterns for the tool 'BlockEtw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockEtw"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/BlockETW-A" nocase ascii wide
                        $string2 = /Trojan\:Win32\/Rozena\.HNB\!MTB/ nocase ascii wide

    condition:
        any of them
}