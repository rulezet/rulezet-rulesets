rule rule_qwinsta_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'qwinsta' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qwinsta"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_qwinsta_greyware_tool_keyword = /cmd\s\/c\s.{0,1000}qwinsta/ nocase ascii wide
                        $string2_qwinsta_greyware_tool_keyword = /cmd\.exe.{0,1000}qwinsta/ nocase ascii wide
                        $string3_qwinsta_greyware_tool_keyword = "qwinsta /server:" nocase ascii wide

    condition:
        any of them
}