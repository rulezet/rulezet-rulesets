rule rule_Hak5_Rubber_Ducky_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Rubber Ducky' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Rubber Ducky"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hak5_Rubber_Ducky_offensive_tool_keyword = /HID\\VID_03EB\&PID_2401\&REV_0100/ nocase ascii wide
                        $string2_Hak5_Rubber_Ducky_offensive_tool_keyword = /HID\\VID_03EB\&PID_2422\&REV_0100/ nocase ascii wide
                        $string3_Hak5_Rubber_Ducky_offensive_tool_keyword = "VID_03EB&PID_2403" nocase ascii wide

    condition:
        any of them
}