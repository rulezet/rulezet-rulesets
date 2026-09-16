rule rule_AhMyth_Android_RAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AhMyth-Android-RAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AhMyth-Android-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AhMyth_Android_RAT_offensive_tool_keyword = "AhMyth-Android-RAT" nocase ascii wide

    condition:
        any of them
}