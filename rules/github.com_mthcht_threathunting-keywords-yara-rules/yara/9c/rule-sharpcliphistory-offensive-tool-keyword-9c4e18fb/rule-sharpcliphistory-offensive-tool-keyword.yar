rule rule_SharpClipHistory_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpClipHistory' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipHistory"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpClipHistory_offensive_tool_keyword = "SharpClipHistory" nocase ascii wide

    condition:
        any of them
}