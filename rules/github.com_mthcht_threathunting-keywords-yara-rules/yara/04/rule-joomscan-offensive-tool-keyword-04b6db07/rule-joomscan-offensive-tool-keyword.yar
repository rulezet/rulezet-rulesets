rule rule_joomscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'joomscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "joomscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_joomscan_offensive_tool_keyword = "joomscan" nocase ascii wide

    condition:
        any of them
}