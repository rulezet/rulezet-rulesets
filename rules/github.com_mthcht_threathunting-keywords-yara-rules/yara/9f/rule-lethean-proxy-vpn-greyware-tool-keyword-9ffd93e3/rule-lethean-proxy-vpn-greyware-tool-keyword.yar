rule rule_Lethean_Proxy_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lethean Proxy VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lethean Proxy VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Lethean_Proxy_VPN_greyware_tool_keyword = "aigmfoeogfnljhnofglledbhhfegannp" nocase ascii wide

    condition:
        any of them
}