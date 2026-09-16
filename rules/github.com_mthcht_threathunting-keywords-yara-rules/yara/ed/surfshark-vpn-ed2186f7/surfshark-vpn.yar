rule surfshark_VPN
{
    meta:
        description = "Detection patterns for the tool 'surfshark VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "surfshark VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /api\.surfshark\.com\// nocase ascii wide
                        $string2 = /downloads\.surfshark\.com/ nocase ascii wide
                        $string3 = /downloads2\.surfshark\.com/ nocase ascii wide
                        $string4 = /prod\.surfshark\.com/ nocase ascii wide

    condition:
        any of them
}