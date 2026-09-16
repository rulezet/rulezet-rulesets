rule Free_Fast_VPN
{
    meta:
        description = "Detection patterns for the tool 'Free Fast VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Fast VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "macdlemfnignjhclfcfichcdhiomgjjb" nocase ascii wide

    condition:
        any of them
}