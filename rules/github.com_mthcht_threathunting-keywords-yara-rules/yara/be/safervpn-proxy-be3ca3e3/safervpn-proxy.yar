rule SaferVPN_Proxy
{
    meta:
        description = "Detection patterns for the tool 'SaferVPN Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SaferVPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "cocfojppfigjeefejbpfmedgjbpchcng" nocase ascii wide

    condition:
        any of them
}