rule Salsa_tools
{
    meta:
        description = "Detection patterns for the tool 'Salsa-tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Salsa-tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Salsa-tools" nocase ascii wide

    condition:
        any of them
}