rule rule_kalitorify_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kalitorify' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kalitorify"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kalitorify_offensive_tool_keyword = "kalitorify"

    condition:
        any of them
}