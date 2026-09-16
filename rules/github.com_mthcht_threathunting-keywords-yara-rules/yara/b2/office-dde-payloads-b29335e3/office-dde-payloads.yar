rule Office_DDE_Payloads
{
    meta:
        description = "Detection patterns for the tool 'Office-DDE-Payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Office-DDE-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Office-DDE-Payloads" nocase ascii wide

    condition:
        any of them
}