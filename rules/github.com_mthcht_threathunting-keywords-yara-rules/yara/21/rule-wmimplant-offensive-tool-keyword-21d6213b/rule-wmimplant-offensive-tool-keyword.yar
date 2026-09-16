rule rule_WMImplant_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMImplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WMImplant_offensive_tool_keyword = /\s\-Remote_Posh\s\-Location\s.{0,1000}\.ps1\s\-Function\sInvoke\-.{0,1000}\s\-ComputerName\s/ nocase ascii wide
                        $string2_WMImplant_offensive_tool_keyword = "Edit-FileWMI" nocase ascii wide
                        $string3_WMImplant_offensive_tool_keyword = "Find-FileWMImplant" nocase ascii wide
                        $string4_WMImplant_offensive_tool_keyword = "Find-VacantComputer" nocase ascii wide
                        $string5_WMImplant_offensive_tool_keyword = "Get-FileContentsWMImplant" nocase ascii wide
                        $string6_WMImplant_offensive_tool_keyword = "Get-WMIEventLogins" nocase ascii wide
                        $string7_WMImplant_offensive_tool_keyword = "Invoke-FileTransferWMImplant" nocase ascii wide
                        $string8_WMImplant_offensive_tool_keyword = "Invoke-LSWMImplant" nocase ascii wide
                        $string9_WMImplant_offensive_tool_keyword = "Invoke-PowerOptionsWMI" nocase ascii wide
                        $string10_WMImplant_offensive_tool_keyword = "Invoke-ProcessPunisher" nocase ascii wide
                        $string11_WMImplant_offensive_tool_keyword = "Invoke-ProcSpawn -Command " nocase ascii wide
                        $string12_WMImplant_offensive_tool_keyword = "Invoke-ProcSpawn" nocase ascii wide
                        $string13_WMImplant_offensive_tool_keyword = "Invoke-RemoteScriptWithOutput" nocase ascii wide
                        $string14_WMImplant_offensive_tool_keyword = "Invoke-WMImplant" nocase ascii wide
                        $string15_WMImplant_offensive_tool_keyword = "Invoke-WMIObfuscatedPSCommand" nocase ascii wide
                        $string16_WMImplant_offensive_tool_keyword = /powershell\.exe\s\-command\s.{0,1000}Enable\-PSRemoting\s\-Force.{0,1000}\s\-ComputerName\s/ nocase ascii wide
                        $string17_WMImplant_offensive_tool_keyword = "Show-WMImplantMainMenu" nocase ascii wide
                        $string18_WMImplant_offensive_tool_keyword = "WMImplant" nocase ascii wide

    condition:
        any of them
}