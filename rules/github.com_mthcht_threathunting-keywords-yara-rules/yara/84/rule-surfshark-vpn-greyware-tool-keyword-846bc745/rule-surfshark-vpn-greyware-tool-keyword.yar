rule rule_surfshark_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'surfshark VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "surfshark VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_surfshark_VPN_greyware_tool_keyword = /api\.surfshark\.com\// nocase ascii wide
                        $string2_surfshark_VPN_greyware_tool_keyword = /downloads\.surfshark\.com/ nocase ascii wide
                        $string3_surfshark_VPN_greyware_tool_keyword = /downloads2\.surfshark\.com/ nocase ascii wide
                        $string4_surfshark_VPN_greyware_tool_keyword = /prod\.surfshark\.com/ nocase ascii wide

    condition:
        any of them
}