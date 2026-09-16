rule Tunnello_VPN
{
    meta:
        description = "Detection patterns for the tool 'Tunnello VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tunnello VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "hoapmlpnmpaehilehggglehfdlnoegck" nocase ascii wide

    condition:
        any of them
}