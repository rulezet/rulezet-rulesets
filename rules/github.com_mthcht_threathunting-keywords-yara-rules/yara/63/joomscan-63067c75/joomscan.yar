rule joomscan
{
    meta:
        description = "Detection patterns for the tool 'joomscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "joomscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "joomscan" nocase ascii wide

    condition:
        any of them
}