rule rule_Dr0p1t_Framework_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dr0p1t-Framework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dr0p1t-Framework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dr0p1t_Framework_offensive_tool_keyword = "Dr0p1t-Framework" nocase ascii wide

    condition:
        any of them
}