rule rule_Tool_PassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tool-PassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tool-PassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Tool_PassView_offensive_tool_keyword = "Tool-PassView" nocase ascii wide

    condition:
        any of them
}