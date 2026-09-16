rule rule_Free_Proxy_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Proxy VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Proxy VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Free_Proxy_VPN_greyware_tool_keyword = "dhadilbmmjiooceioladdphemaliiobo" nocase ascii wide
                        $string2_Free_Proxy_VPN_greyware_tool_keyword = "pgfpignfckbloagkfnamnolkeaecfgfh" nocase ascii wide

    condition:
        any of them
}