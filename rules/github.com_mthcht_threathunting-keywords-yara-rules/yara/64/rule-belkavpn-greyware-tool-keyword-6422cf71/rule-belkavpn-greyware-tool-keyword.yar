rule rule_BelkaVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BelkaVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BelkaVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_BelkaVPN_greyware_tool_keyword = "npgimkapccfidfkfoklhpkgmhgfejhbj" nocase ascii wide

    condition:
        any of them
}