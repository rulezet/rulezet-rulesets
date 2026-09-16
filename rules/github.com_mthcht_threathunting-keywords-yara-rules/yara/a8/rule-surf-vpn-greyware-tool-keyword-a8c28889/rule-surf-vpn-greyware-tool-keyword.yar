rule rule_Surf_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Surf VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Surf VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Surf_VPN_greyware_tool_keyword = "nhnfcgpcbfclhfafjlooihdfghaeinfc" nocase ascii wide

    condition:
        any of them
}