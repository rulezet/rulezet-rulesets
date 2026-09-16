rule rule_archstrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'archstrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "archstrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_archstrike_offensive_tool_keyword = "ArchStrike"

    condition:
        any of them
}