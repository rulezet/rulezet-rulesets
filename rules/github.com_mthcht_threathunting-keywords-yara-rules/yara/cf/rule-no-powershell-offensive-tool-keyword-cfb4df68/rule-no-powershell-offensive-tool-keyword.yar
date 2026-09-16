rule rule_No_powershell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'No-powershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "No-powershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_No_powershell_offensive_tool_keyword = /\sNo\-PowerShell\.cs/ nocase ascii wide
                        $string2_No_powershell_offensive_tool_keyword = /\/No\-PowerShell\.cs/ nocase ascii wide
                        $string3_No_powershell_offensive_tool_keyword = /\/No\-PowerShell\.exe/ nocase ascii wide
                        $string4_No_powershell_offensive_tool_keyword = /\\No\-PowerShell\.cs/ nocase ascii wide
                        $string5_No_powershell_offensive_tool_keyword = /\\No\-PowerShell\.exe/ nocase ascii wide
                        $string6_No_powershell_offensive_tool_keyword = /c\:\\temp\\something\.ps1/ nocase ascii wide

    condition:
        any of them
}