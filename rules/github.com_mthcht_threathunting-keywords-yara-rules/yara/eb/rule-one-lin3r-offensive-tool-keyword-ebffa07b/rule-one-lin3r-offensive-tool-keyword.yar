rule rule_One_Lin3r_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'One-Lin3r' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "One-Lin3r"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_One_Lin3r_offensive_tool_keyword = "One-Lin3r"

    condition:
        any of them
}