rule rule_HMA_VPN_Proxy_Unblocker_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HMA VPN Proxy Unblocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HMA VPN Proxy Unblocker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_HMA_VPN_Proxy_Unblocker_greyware_tool_keyword = "poeojclicodamonabcabmapamjkkmnnk" nocase ascii wide

    condition:
        any of them
}