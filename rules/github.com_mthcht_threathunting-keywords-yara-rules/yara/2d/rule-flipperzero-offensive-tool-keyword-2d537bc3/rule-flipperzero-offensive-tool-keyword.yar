rule rule_FlipperZero_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FlipperZero' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FlipperZero"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FlipperZero_offensive_tool_keyword = "VID_0483&PID_5740" nocase ascii wide

    condition:
        any of them
}