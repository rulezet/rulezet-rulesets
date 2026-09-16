rule rule_Red_Baron_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Red-Baron' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Red-Baron"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Red_Baron_offensive_tool_keyword = "Red-Baron" nocase ascii wide

    condition:
        any of them
}