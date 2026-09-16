rule rule_Unlimited_VPN__and__Proxy_by_ibVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Unlimited VPN & Proxy by ibVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Unlimited VPN & Proxy by ibVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Unlimited_VPN__and__Proxy_by_ibVPN_greyware_tool_keyword = "higioemojdadgdbhbbbkfbebbdlfjbip" nocase ascii wide

    condition:
        any of them
}