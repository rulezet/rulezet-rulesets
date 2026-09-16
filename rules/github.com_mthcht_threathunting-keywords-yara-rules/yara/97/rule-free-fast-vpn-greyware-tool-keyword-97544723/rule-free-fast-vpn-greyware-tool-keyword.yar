rule rule_Free_Fast_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Fast VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Fast VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Free_Fast_VPN_greyware_tool_keyword = "macdlemfnignjhclfcfichcdhiomgjjb" nocase ascii wide

    condition:
        any of them
}