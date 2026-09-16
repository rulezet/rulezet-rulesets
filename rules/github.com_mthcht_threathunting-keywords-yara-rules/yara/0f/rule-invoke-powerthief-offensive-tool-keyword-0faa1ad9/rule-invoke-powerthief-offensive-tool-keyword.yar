rule rule_Invoke_PowerThIEf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PowerThIEf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PowerThIEf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_PowerThIEf_offensive_tool_keyword = "Invoke-PowerThIEf" nocase ascii wide

    condition:
        any of them
}