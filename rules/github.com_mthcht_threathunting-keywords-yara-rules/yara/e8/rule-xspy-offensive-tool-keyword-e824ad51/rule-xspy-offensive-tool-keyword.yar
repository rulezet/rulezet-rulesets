rule rule_xspy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xspy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xspy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_xspy_offensive_tool_keyword = "xspy -display" nocase ascii wide

    condition:
        any of them
}