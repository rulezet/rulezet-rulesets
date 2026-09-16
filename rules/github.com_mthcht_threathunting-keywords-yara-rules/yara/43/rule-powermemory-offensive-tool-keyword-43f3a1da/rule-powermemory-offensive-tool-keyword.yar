rule rule_PowerMemory_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerMemory' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerMemory"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerMemory_offensive_tool_keyword = "PowerMemory" nocase ascii wide

    condition:
        any of them
}