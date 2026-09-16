rule rule_enum4linux_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'enum4linux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "enum4linux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_enum4linux_offensive_tool_keyword = "enum4linux"

    condition:
        any of them
}