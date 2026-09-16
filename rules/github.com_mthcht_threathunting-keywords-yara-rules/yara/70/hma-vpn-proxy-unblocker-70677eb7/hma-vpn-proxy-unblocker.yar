rule HMA_VPN_Proxy_Unblocker
{
    meta:
        description = "Detection patterns for the tool 'HMA VPN Proxy Unblocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HMA VPN Proxy Unblocker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "poeojclicodamonabcabmapamjkkmnnk" nocase ascii wide

    condition:
        any of them
}