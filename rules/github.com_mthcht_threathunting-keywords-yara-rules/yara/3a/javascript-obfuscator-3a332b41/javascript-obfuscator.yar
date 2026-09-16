rule javascript_obfuscator
{
    meta:
        description = "Detection patterns for the tool 'javascript-obfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "javascript-obfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "javascript-obfuscator" nocase ascii wide

    condition:
        any of them
}