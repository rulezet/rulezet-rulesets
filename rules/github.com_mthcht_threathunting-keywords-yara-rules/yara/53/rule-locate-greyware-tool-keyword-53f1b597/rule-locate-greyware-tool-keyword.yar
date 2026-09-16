rule rule_locate_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'locate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "locate"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_locate_greyware_tool_keyword = /locate\spassword\s\|\smore/ nocase ascii wide

    condition:
        any of them
}