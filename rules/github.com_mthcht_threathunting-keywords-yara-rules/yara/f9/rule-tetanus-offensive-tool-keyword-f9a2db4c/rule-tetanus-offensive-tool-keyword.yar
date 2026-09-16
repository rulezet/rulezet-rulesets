rule rule_tetanus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tetanus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tetanus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tetanus_offensive_tool_keyword = /\.\/mythic\-cli\s/
                        $string2_tetanus_offensive_tool_keyword = "MythicAgents/tetanus" nocase ascii wide
                        $string3_tetanus_offensive_tool_keyword = "payload start tetanus" nocase ascii wide

    condition:
        any of them
}