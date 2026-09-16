rule rule_Daily_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Daily VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Daily VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Daily_VPN_greyware_tool_keyword = "namfblliamklmeodpcelkokjbffgmeoo" nocase ascii wide

    condition:
        any of them
}