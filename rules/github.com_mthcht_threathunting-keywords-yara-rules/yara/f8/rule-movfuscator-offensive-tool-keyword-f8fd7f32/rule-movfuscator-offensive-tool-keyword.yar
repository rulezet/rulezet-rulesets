rule rule_movfuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'movfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "movfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_movfuscator_offensive_tool_keyword = "movfuscator" nocase ascii wide

    condition:
        any of them
}