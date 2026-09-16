rule rule_Wachee_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Wachee VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Wachee VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Wachee_VPN_greyware_tool_keyword = "bhnhkdgoefpmekcgnccpnhjfdgicfebm" nocase ascii wide

    condition:
        any of them
}