rule rule_PowerForensics_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerForensics' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerForensics"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerForensics_offensive_tool_keyword = "PowerForensics" nocase ascii wide

    condition:
        any of them
}