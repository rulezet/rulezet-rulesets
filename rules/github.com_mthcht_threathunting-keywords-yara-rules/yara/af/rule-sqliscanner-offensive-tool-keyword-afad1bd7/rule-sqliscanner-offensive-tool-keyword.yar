rule rule_SQLiScanner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SQLiScanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLiScanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SQLiScanner_offensive_tool_keyword = "SQLiScanner" nocase ascii wide

    condition:
        any of them
}