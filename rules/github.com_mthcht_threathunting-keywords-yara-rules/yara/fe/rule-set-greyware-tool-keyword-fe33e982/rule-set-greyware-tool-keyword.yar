rule rule_set_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'set' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "set"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_set_greyware_tool_keyword = /cmd\s\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
                        $string2_set_greyware_tool_keyword = /cmd\.exe\s\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
                        $string3_set_greyware_tool_keyword = /cmd\.exe.{0,1000}\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
                        $string4_set_greyware_tool_keyword = /set\s\+o\shistory/ nocase ascii wide

    condition:
        any of them
}