rule NordVPN
{
    meta:
        description = "Detection patterns for the tool 'NordVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NordVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /downloads\.nordcdn\.com\/apps\/vpn\-extension\// nocase ascii wide
                        $string2 = "fjoaledfpmneenckfbpdfhkmimnjocfa" nocase ascii wide
                        $string3 = /https\:\/\/nordvpn\.com.{0,1000}\/ovpn\/.{0,1000}\.ovpn/ nocase ascii wide

    condition:
        any of them
}