rule One_Lin3r
{
    meta:
        description = "Detection patterns for the tool 'One-Lin3r' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "One-Lin3r"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "One-Lin3r"

    condition:
        any of them
}