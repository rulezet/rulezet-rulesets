rule Fornex_VPN
{
    meta:
        description = "Detection patterns for the tool 'Fornex VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fornex VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "egblhcjfjmbjajhjhpmnlekffgaemgfh" nocase ascii wide

    condition:
        any of them
}