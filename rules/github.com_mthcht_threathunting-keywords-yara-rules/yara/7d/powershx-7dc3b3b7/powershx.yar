rule PowerShx
{
    meta:
        description = "Detection patterns for the tool 'PowerShx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PowerShx\.git/ nocase ascii wide
                        $string2 = "1E70D62D-CC36-480F-82BB-E9593A759AF9" nocase ascii wide
                        $string3 = "A17656B2-42D1-42CD-B76D-9B60F637BCB5" nocase ascii wide
                        $string4 = "iomoath/PowerShx" nocase ascii wide
                        $string5 = /PowerShx\.dll/ nocase ascii wide
                        $string6 = /PowerShx\.exe/ nocase ascii wide
                        $string7 = /PowerShx\.sln/ nocase ascii wide
                        $string8 = /PowerShxDll\.csproj/ nocase ascii wide
                        $string9 = "PowerShx-master" nocase ascii wide

    condition:
        any of them
}