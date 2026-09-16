rule rule_theHarvester_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'theHarvester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "theHarvester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_theHarvester_offensive_tool_keyword = "theHarvester" nocase ascii wide

    condition:
        any of them
}