rule rule_username_anarchy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'username-anarchy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "username-anarchy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_username_anarchy_offensive_tool_keyword = "/username-anarchy" nocase ascii wide
                        $string2_username_anarchy_offensive_tool_keyword = "username-anarchy " nocase ascii wide

    condition:
        any of them
}