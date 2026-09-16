rule gobfuscate
{
    meta:
        description = "Detection patterns for the tool 'gobfuscate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobfuscate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "gobfuscate" nocase ascii wide

    condition:
        any of them
}