rule Hotspot_Shield_Elite_VPN_Proxy
{
    meta:
        description = "Detection patterns for the tool 'Hotspot Shield Elite VPN Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hotspot Shield Elite VPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ejkaocphofnobjdedneohbbiilggdlbi" nocase ascii wide

    condition:
        any of them
}