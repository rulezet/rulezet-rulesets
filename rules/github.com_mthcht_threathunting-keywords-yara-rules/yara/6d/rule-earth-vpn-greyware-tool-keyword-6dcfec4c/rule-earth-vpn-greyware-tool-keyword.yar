rule rule_Earth_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Earth VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Earth_VPN_greyware_tool_keyword = "nabbmpekekjknlbkgpodfndbodhijjem" nocase ascii wide

    condition:
        any of them
}