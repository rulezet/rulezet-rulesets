rule Tool_PassView
{
    meta:
        description = "Detection patterns for the tool 'Tool-PassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tool-PassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Tool-PassView" nocase ascii wide

    condition:
        any of them
}