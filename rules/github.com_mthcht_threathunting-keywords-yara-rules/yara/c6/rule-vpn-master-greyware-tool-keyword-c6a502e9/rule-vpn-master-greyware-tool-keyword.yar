rule rule_VPN_Master_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Master' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Master"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_VPN_Master_greyware_tool_keyword = "akeehkgglkmpapdnanoochpfmeghfdln" nocase ascii wide

    condition:
        any of them
}