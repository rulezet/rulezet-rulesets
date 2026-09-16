rule Astar_VPN
{
    meta:
        description = "Detection patterns for the tool 'Astar VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Astar VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "jajilbjjinjmgcibalaakngmkilboobh" nocase ascii wide

    condition:
        any of them
}