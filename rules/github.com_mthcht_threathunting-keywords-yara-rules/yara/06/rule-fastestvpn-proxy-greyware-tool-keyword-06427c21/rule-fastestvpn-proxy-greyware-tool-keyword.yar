rule rule_FastestVPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FastestVPN Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FastestVPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_FastestVPN_Proxy_greyware_tool_keyword = "jedieiamjmoflcknjdjhpieklepfglin" nocase ascii wide

    condition:
        any of them
}