rule username_anarchy
{
    meta:
        description = "Detection patterns for the tool 'username-anarchy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "username-anarchy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/username-anarchy" nocase ascii wide
                        $string2 = "username-anarchy " nocase ascii wide

    condition:
        any of them
}