rule Hak5_Wifi_Pineapple
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Wifi Pineapple' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Wifi Pineapple"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /USB\\VID_0B95\&PID_772A\\90CEA2/ nocase ascii wide

    condition:
        any of them
}