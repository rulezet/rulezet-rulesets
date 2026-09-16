rule rule_Ultrareach_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ultrareach VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ultrareach VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Ultrareach_VPN_greyware_tool_keyword = "mjnbclmflcpookeapghfhapeffmpodij" nocase ascii wide

    condition:
        any of them
}