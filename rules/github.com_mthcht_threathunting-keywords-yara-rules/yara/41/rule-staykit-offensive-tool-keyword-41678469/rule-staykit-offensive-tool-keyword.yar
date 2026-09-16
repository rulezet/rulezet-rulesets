rule rule_StayKit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'StayKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StayKit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_StayKit_offensive_tool_keyword = "/0xthirteen/StayKit" nocase ascii wide
                        $string2_StayKit_offensive_tool_keyword = "BackdoorLNK" nocase ascii wide
                        $string3_StayKit_offensive_tool_keyword = /StayKit\.cna/ nocase ascii wide

    condition:
        any of them
}