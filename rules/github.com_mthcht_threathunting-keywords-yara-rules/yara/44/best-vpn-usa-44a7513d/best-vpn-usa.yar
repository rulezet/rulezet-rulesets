rule Best_VPN_USA
{
    meta:
        description = "Detection patterns for the tool 'Best VPN USA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Best VPN USA"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ficajfeojakddincjafebjmfiefcmanc" nocase ascii wide

    condition:
        any of them
}