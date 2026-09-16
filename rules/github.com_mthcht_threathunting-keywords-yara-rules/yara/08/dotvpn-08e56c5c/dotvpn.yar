rule DotVPN
{
    meta:
        description = "Detection patterns for the tool 'DotVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DotVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "kpiecbcckbofpmkkkdibbllpinceiihk" nocase ascii wide
                        $string2 = "mjolnodfokkkaichkcjipfgblbfgojpa" nocase ascii wide

    condition:
        any of them
}