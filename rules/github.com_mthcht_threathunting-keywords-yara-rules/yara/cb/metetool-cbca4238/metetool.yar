rule MeteTool
{
    meta:
        description = "Detection patterns for the tool 'MeteTool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MeteTool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "MeteTool" nocase ascii wide

    condition:
        any of them
}