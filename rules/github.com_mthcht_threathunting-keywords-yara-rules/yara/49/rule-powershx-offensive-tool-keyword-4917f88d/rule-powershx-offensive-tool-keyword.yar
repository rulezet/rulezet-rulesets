rule rule_PowerShx_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerShx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerShx_offensive_tool_keyword = /\/PowerShx\.git/ nocase ascii wide
                        $string2_PowerShx_offensive_tool_keyword = "1E70D62D-CC36-480F-82BB-E9593A759AF9" nocase ascii wide
                        $string3_PowerShx_offensive_tool_keyword = "A17656B2-42D1-42CD-B76D-9B60F637BCB5" nocase ascii wide
                        $string4_PowerShx_offensive_tool_keyword = "iomoath/PowerShx" nocase ascii wide
                        $string5_PowerShx_offensive_tool_keyword = /PowerShx\.dll/ nocase ascii wide
                        $string6_PowerShx_offensive_tool_keyword = /PowerShx\.exe/ nocase ascii wide
                        $string7_PowerShx_offensive_tool_keyword = /PowerShx\.sln/ nocase ascii wide
                        $string8_PowerShx_offensive_tool_keyword = /PowerShxDll\.csproj/ nocase ascii wide
                        $string9_PowerShx_offensive_tool_keyword = "PowerShx-master" nocase ascii wide

    condition:
        any of them
}