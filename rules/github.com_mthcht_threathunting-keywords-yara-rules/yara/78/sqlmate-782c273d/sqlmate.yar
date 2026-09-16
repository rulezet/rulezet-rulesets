rule SQLmate
{
    meta:
        description = "Detection patterns for the tool 'SQLmate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLmate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "SQLmate" nocase ascii wide

    condition:
        any of them
}