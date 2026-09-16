rule rule_VPN_Free_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Free' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Free"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_VPN_Free_greyware_tool_keyword = "gjknjjomckknofjidppipffbpoekiipm" nocase ascii wide

    condition:
        any of them
}