rule rule_Invoke_ZeroLogon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ZeroLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ZeroLogon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_ZeroLogon_offensive_tool_keyword = "Invoke-ZeroLogon" nocase ascii wide

    condition:
        any of them
}