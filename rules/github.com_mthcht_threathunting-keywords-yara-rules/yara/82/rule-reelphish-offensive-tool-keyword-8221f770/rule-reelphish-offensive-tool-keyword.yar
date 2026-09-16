rule rule_ReelPhish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ReelPhish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReelPhish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ReelPhish_offensive_tool_keyword = "ReelPhish" nocase ascii wide

    condition:
        any of them
}