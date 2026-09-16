rule Free_Proxy_VPN
{
    meta:
        description = "Detection patterns for the tool 'Free Proxy VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Proxy VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "dhadilbmmjiooceioladdphemaliiobo" nocase ascii wide
                        $string2 = "pgfpignfckbloagkfnamnolkeaecfgfh" nocase ascii wide

    condition:
        any of them
}