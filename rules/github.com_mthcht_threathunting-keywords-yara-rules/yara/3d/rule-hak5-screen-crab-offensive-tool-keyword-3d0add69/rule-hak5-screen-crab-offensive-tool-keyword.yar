rule rule_Hak5_Screen_Crab_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Screen Crab' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Screen Crab"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hak5_Screen_Crab_offensive_tool_keyword = /USB\\VID_18D1\&PID_4EE7\\KYLIN/ nocase ascii wide

    condition:
        any of them
}