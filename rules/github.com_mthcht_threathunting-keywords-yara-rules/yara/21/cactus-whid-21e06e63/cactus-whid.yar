rule Cactus_WHID
{
    meta:
        description = "Detection patterns for the tool 'Cactus WHID' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cactus WHID"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /HID\\VID_1B4F\&PID_9207/ nocase ascii wide
                        $string2 = /USB\\VID_1B4F\&PID_9208/ nocase ascii wide

    condition:
        any of them
}