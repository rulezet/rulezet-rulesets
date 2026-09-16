rule rule_Advanced_SQL_Injection_Cheatsheet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Advanced-SQL-Injection-Cheatsheet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Advanced-SQL-Injection-Cheatsheet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Advanced_SQL_Injection_Cheatsheet_offensive_tool_keyword = "Advanced-SQL-Injection-Cheatsheet" nocase ascii wide

    condition:
        any of them
}