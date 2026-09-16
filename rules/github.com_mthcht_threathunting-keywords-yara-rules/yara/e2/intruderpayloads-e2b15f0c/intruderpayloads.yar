rule IntruderPayloads
{
    meta:
        description = "Detection patterns for the tool 'IntruderPayloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IntruderPayloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "IntruderPayloads" nocase ascii wide

    condition:
        any of them
}