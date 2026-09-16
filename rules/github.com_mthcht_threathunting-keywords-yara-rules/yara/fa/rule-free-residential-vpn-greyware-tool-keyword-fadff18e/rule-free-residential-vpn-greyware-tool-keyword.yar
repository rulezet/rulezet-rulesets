rule rule_Free_Residential_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Residential VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Residential VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Free_Residential_VPN_greyware_tool_keyword = "jpgljfpmoofbmlieejglhonfofmahini" nocase ascii wide

    condition:
        any of them
}