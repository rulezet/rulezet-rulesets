rule rule_Invoke_BSOD_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-BSOD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-BSOD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_BSOD_offensive_tool_keyword = "Invoke-BSOD" nocase ascii wide

    condition:
        any of them
}