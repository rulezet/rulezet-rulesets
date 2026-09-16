rule rule_NordVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NordVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NordVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_NordVPN_greyware_tool_keyword = /downloads\.nordcdn\.com\/apps\/vpn\-extension\// nocase ascii wide
                        $string2_NordVPN_greyware_tool_keyword = "fjoaledfpmneenckfbpdfhkmimnjocfa" nocase ascii wide
                        $string3_NordVPN_greyware_tool_keyword = /https\:\/\/nordvpn\.com.{0,1000}\/ovpn\/.{0,1000}\.ovpn/ nocase ascii wide

    condition:
        any of them
}