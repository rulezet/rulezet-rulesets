rule rule_red_hawk_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'red_hawk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "red_hawk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_red_hawk_offensive_tool_keyword = "RED_HAWK" nocase ascii wide

    condition:
        any of them
}