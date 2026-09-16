rule rule_MaliciousMacroGenerator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MaliciousMacroGenerator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaliciousMacroGenerator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MaliciousMacroGenerator_offensive_tool_keyword = "MaliciousMacroGenerator" nocase ascii wide

    condition:
        any of them
}