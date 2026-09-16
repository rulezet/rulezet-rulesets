rule al_khaser
{
    meta:
        description = "Detection patterns for the tool 'al-khaser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "al-khaser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "al-khaser" nocase ascii wide

    condition:
        any of them
}