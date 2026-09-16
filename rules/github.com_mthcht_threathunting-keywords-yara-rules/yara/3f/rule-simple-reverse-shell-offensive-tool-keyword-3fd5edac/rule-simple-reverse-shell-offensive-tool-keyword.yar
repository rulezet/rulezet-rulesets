rule rule_Simple_Reverse_Shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Simple-Reverse-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Simple-Reverse-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Simple_Reverse_Shell_offensive_tool_keyword = "/Simple-Reverse-Shell" nocase ascii wide

    condition:
        any of them
}