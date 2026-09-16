rule rule_Tunnello_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tunnello VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tunnello VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Tunnello_VPN_greyware_tool_keyword = "hoapmlpnmpaehilehggglehfdlnoegck" nocase ascii wide

    condition:
        any of them
}