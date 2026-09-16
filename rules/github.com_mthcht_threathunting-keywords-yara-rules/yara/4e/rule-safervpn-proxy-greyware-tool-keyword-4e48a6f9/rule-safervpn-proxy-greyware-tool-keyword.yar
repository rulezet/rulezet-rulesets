rule rule_SaferVPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SaferVPN Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SaferVPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SaferVPN_Proxy_greyware_tool_keyword = "cocfojppfigjeefejbpfmedgjbpchcng" nocase ascii wide

    condition:
        any of them
}