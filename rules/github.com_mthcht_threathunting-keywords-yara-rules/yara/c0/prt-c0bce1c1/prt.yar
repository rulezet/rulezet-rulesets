rule PRT
{
    meta:
        description = "Detection patterns for the tool 'PRT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PRT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Exploitation Toolkit"

    condition:
        any of them
}