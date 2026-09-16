rule SQLiScanner
{
    meta:
        description = "Detection patterns for the tool 'SQLiScanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLiScanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "SQLiScanner" nocase ascii wide

    condition:
        any of them
}