rule rule_DotVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DotVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DotVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_DotVPN_greyware_tool_keyword = "kpiecbcckbofpmkkkdibbllpinceiihk" nocase ascii wide
                        $string2_DotVPN_greyware_tool_keyword = "mjolnodfokkkaichkcjipfgblbfgojpa" nocase ascii wide

    condition:
        any of them
}