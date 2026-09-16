rule tetanus
{
    meta:
        description = "Detection patterns for the tool 'tetanus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tetanus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/mythic\-cli\s/
                        $string2 = "MythicAgents/tetanus" nocase ascii wide
                        $string3 = "payload start tetanus" nocase ascii wide

    condition:
        any of them
}