rule rule_Invoke_PrintDemon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PrintDemon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PrintDemon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_PrintDemon_offensive_tool_keyword = "Invoke-PrintDemon" nocase ascii wide

    condition:
        any of them
}