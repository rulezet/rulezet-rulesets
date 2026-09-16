rule rule_Urban_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Urban Free VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Urban Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Urban_Free_VPN_greyware_tool_keyword = "eppiocemhmnlbhjplcgkofciiegomcon" nocase ascii wide

    condition:
        any of them
}