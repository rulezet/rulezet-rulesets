rule rule_al_khaser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'al-khaser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "al-khaser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_al_khaser_offensive_tool_keyword = "al-khaser" nocase ascii wide

    condition:
        any of them
}