rule rule_touch_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'touch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "touch"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_touch_greyware_tool_keyword = "touch -a" nocase ascii wide
                        $string2_touch_greyware_tool_keyword = "touch -m" nocase ascii wide
                        $string3_touch_greyware_tool_keyword = "touch -t " nocase ascii wide

    condition:
        any of them
}