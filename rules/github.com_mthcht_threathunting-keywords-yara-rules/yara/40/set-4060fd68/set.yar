rule set
{
    meta:
        description = "Detection patterns for the tool 'set' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "set"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cmd\s\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
                        $string2 = /cmd\.exe\s\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
                        $string3 = /cmd\.exe.{0,1000}\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
                        $string4 = /set\s\+o\shistory/ nocase ascii wide

    condition:
        any of them
}