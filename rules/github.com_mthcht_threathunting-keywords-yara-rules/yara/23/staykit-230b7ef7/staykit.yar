rule StayKit
{
    meta:
        description = "Detection patterns for the tool 'StayKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StayKit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/0xthirteen/StayKit" nocase ascii wide
                        $string2 = "BackdoorLNK" nocase ascii wide
                        $string3 = /StayKit\.cna/ nocase ascii wide

    condition:
        any of them
}