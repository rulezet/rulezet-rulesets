rule WMImplant
{
    meta:
        description = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMImplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-Remote_Posh\s\-Location\s.{0,1000}\.ps1\s\-Function\sInvoke\-.{0,1000}\s\-ComputerName\s/ nocase ascii wide
                        $string2 = "Edit-FileWMI" nocase ascii wide
                        $string3 = "Find-FileWMImplant" nocase ascii wide
                        $string4 = "Find-VacantComputer" nocase ascii wide
                        $string5 = "Get-FileContentsWMImplant" nocase ascii wide
                        $string6 = "Get-WMIEventLogins" nocase ascii wide
                        $string7 = "Invoke-FileTransferWMImplant" nocase ascii wide
                        $string8 = "Invoke-LSWMImplant" nocase ascii wide
                        $string9 = "Invoke-PowerOptionsWMI" nocase ascii wide
                        $string10 = "Invoke-ProcessPunisher" nocase ascii wide
                        $string11 = "Invoke-ProcSpawn -Command " nocase ascii wide
                        $string12 = "Invoke-ProcSpawn" nocase ascii wide
                        $string13 = "Invoke-RemoteScriptWithOutput" nocase ascii wide
                        $string14 = "Invoke-WMImplant" nocase ascii wide
                        $string15 = "Invoke-WMIObfuscatedPSCommand" nocase ascii wide
                        $string16 = /powershell\.exe\s\-command\s.{0,1000}Enable\-PSRemoting\s\-Force.{0,1000}\s\-ComputerName\s/ nocase ascii wide
                        $string17 = "Show-WMImplantMainMenu" nocase ascii wide
                        $string18 = "WMImplant" nocase ascii wide

    condition:
        any of them
}