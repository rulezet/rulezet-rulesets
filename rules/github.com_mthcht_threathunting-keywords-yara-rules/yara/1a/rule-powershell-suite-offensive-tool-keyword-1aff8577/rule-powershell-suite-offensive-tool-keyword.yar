rule rule_PowerShell_Suite_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerShell-Suite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShell-Suite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerShell_Suite_offensive_tool_keyword = "PowerShell-Suite" nocase ascii wide

    condition:
        any of them
}