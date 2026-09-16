rule rule_Git_Scanner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Git-Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Git-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Git_Scanner_offensive_tool_keyword = "Git-Scanner" nocase ascii wide

    condition:
        any of them
}