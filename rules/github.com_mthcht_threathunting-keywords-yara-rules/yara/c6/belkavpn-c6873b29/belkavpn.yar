rule BelkaVPN
{
    meta:
        description = "Detection patterns for the tool 'BelkaVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BelkaVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "npgimkapccfidfkfoklhpkgmhgfejhbj" nocase ascii wide

    condition:
        any of them
}