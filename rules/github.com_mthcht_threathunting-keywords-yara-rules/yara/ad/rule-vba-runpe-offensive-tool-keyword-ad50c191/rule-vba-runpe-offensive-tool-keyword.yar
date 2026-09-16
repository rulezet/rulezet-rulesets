rule rule_VBA_RunPE_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VBA-RunPE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VBA-RunPE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_VBA_RunPE_offensive_tool_keyword = "VBA-RunPE -" nocase ascii wide

    condition:
        any of them
}