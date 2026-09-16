rule Wachee_VPN
{
    meta:
        description = "Detection patterns for the tool 'Wachee VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Wachee VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bhnhkdgoefpmekcgnccpnhjfdgicfebm" nocase ascii wide

    condition:
        any of them
}