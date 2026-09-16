rule rule_MeteTool_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MeteTool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MeteTool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MeteTool_offensive_tool_keyword = "MeteTool" nocase ascii wide

    condition:
        any of them
}