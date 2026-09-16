rule rule_Invoke_PowerIncrease_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PowerIncrease' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PowerIncrease"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_PowerIncrease_offensive_tool_keyword = "42e42476084102789dfef4a1369a3028c2319de6a34ba704db907dedf63e2b29" nocase ascii wide
                        $string2_Invoke_PowerIncrease_offensive_tool_keyword = "Invoke-PowerIncrease -SourceFilePath " nocase ascii wide
                        $string3_Invoke_PowerIncrease_offensive_tool_keyword = /Invoke\-PowerIncrease\.ps1/ nocase ascii wide
                        $string4_Invoke_PowerIncrease_offensive_tool_keyword = "The-Viper-One/Invoke-PowerIncrease" nocase ascii wide

    condition:
        any of them
}