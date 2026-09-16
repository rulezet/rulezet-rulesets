rule Hak5_Lan_turtle
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Lan turtle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Lan turtle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /USB\\VID_0BDA\&PID_8152\\00E04C361BDE/ nocase ascii wide
                        $string2 = /USB\\VID_0BDA\&PID_8152\\00E04C3659E9/ nocase ascii wide

    condition:
        any of them
}