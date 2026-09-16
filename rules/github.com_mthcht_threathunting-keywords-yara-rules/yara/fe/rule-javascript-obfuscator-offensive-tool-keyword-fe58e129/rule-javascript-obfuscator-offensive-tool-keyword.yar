rule rule_javascript_obfuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'javascript-obfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "javascript-obfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_javascript_obfuscator_offensive_tool_keyword = "javascript-obfuscator" nocase ascii wide

    condition:
        any of them
}