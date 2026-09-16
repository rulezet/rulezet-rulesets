rule ghidra
{
    meta:
        description = "Detection patterns for the tool 'ghidra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghidra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ghidra" nocase ascii wide

    condition:
        any of them
}