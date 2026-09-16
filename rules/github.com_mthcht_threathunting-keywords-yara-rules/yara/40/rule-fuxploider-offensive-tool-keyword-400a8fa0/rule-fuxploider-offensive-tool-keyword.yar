rule rule_fuxploider_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fuxploider' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuxploider"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fuxploider_offensive_tool_keyword = "fuxploider" nocase ascii wide

    condition:
        any of them
}