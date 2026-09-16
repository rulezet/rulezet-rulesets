rule rule_mousejack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mousejack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mousejack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mousejack_offensive_tool_keyword = "mousejack" nocase ascii wide

    condition:
        any of them
}