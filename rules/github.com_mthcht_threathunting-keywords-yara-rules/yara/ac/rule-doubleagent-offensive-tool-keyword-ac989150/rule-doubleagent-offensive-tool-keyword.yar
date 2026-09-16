rule rule_DoubleAgent_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DoubleAgent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoubleAgent"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DoubleAgent_offensive_tool_keyword = /DoubleAgent\.sln/ nocase ascii wide

    condition:
        any of them
}