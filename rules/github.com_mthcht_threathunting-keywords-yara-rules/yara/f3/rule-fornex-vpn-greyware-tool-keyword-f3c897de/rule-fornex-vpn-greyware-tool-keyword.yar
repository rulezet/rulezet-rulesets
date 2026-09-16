rule rule_Fornex_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Fornex VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fornex VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Fornex_VPN_greyware_tool_keyword = "egblhcjfjmbjajhjhpmnlekffgaemgfh" nocase ascii wide

    condition:
        any of them
}