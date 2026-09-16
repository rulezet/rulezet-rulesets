rule rule_gobfuscate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gobfuscate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobfuscate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gobfuscate_offensive_tool_keyword = "gobfuscate" nocase ascii wide

    condition:
        any of them
}