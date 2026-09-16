rule Digispark_Attiny85
{
    meta:
        description = "Detection patterns for the tool 'Digispark Attiny85' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Digispark Attiny85"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /USB\\VID_16D0\&PID_0753/ nocase ascii wide

    condition:
        any of them
}