rule Arduino_Pro_Micro
{
    meta:
        description = "Detection patterns for the tool 'Arduino Pro Micro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Arduino Pro Micro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /USB\\VID_2341\&PID_8037/ nocase ascii wide

    condition:
        any of them
}