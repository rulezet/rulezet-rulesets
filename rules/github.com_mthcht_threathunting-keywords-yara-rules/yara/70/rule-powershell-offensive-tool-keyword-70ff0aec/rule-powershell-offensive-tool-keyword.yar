rule rule_powershell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_powershell_offensive_tool_keyword = " imaohw" nocase ascii wide
                        $string2_powershell_offensive_tool_keyword = " resu ten" nocase ascii wide
                        $string3_powershell_offensive_tool_keyword = "//:ptth" nocase ascii wide
                        $string4_powershell_offensive_tool_keyword = "//:sptth" nocase ascii wide
                        $string5_powershell_offensive_tool_keyword = /\[Reflection\.Assembly\]\:\:LoadWithPartialName\(\'System\.Core\'\)\.GetType\(\'System\.Diagnostics\.Eventing\.EventProvider\'\)\.GetField\(\'m_enabled\'.{0,1000}\'NonPublic.{0,1000}Instance\'\)\.SetValue\(\[Ref\]\.Assembly\.GetType\(\'System\.Management\.Automation\.Tracing\.PSEtwLogProvider\'\)\.GetField\(\'etwProvider\'.{0,1000}\'NonPublic.{0,1000}Static\'\)\.GetValue\(\$null\).{0,1000}0\)/ nocase ascii wide
                        $string6_powershell_offensive_tool_keyword = /\\\:MLKH/ nocase ascii wide
                        $string7_powershell_offensive_tool_keyword = /\\\\\:C/ nocase ascii wide
                        $string8_powershell_offensive_tool_keyword = /\\\\ataDmargorP\\\\\:C/ nocase ascii wide
                        $string9_powershell_offensive_tool_keyword = /\\\\swodniW\\\\\:C/ nocase ascii wide
                        $string10_powershell_offensive_tool_keyword = /\\ataDmargorP\\\:C/ nocase ascii wide
                        $string11_powershell_offensive_tool_keyword = /\\erawtfoS\\UCKH/ nocase ascii wide
                        $string12_powershell_offensive_tool_keyword = /\\swodniW\\\:C/ nocase ascii wide
                        $string13_powershell_offensive_tool_keyword = "=imaohw" nocase ascii wide
                        $string14_powershell_offensive_tool_keyword = "=resu ten" nocase ascii wide
                        $string15_powershell_offensive_tool_keyword = "Add-MpPreference -DisableBehaviorMonitoring True" nocase ascii wide
                        $string16_powershell_offensive_tool_keyword = "Add-MpPreference -DisableBehaviourMonitoring True" nocase ascii wide
                        $string17_powershell_offensive_tool_keyword = "Add-MpPreference -DisDisableRealtimeMonitoring True" nocase ascii wide
                        $string18_powershell_offensive_tool_keyword = "Add-MpPreference -ExclusionPath " nocase ascii wide
                        $string19_powershell_offensive_tool_keyword = /Add\-MpPreference\s\-ExclustionPath\sc\:\\users\\public/ nocase ascii wide
                        $string20_powershell_offensive_tool_keyword = /azuread_decrypt_msol_.{0,1000}\.ps1/ nocase ascii wide
                        $string21_powershell_offensive_tool_keyword = /cilbuP\\\\sresU\\\\\:C/ nocase ascii wide
                        $string22_powershell_offensive_tool_keyword = /cilbuP\\sresU\\\:C/ nocase ascii wide
                        $string23_powershell_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C\s.{0,1000}\\temp/ nocase ascii wide
                        $string24_powershell_offensive_tool_keyword = /Get\-ADComputer\s.{0,1000}\s\-Properties\sPrincipalsAllowedToDelegateToAccount/ nocase ascii wide
                        $string25_powershell_offensive_tool_keyword = /Get\-Cluster\|Set\-Cluster\s\-HAEnabled\:\$false\s\-DrsEnabled\:\$false/ nocase ascii wide
                        $string26_powershell_offensive_tool_keyword = /http\:\/\/.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string27_powershell_offensive_tool_keyword = /https\:\/\/.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string28_powershell_offensive_tool_keyword = /Import\-Module\s.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string29_powershell_offensive_tool_keyword = "Invoke-SDPropagator" nocase ascii wide
                        $string30_powershell_offensive_tool_keyword = "llehsrewop" nocase ascii wide
                        $string31_powershell_offensive_tool_keyword = /New\-ItemProperty\s.{0,1000}\s\\"EnableModuleLogging\\"\s\-PropertyType\sDWord\s\-Value\s0/ nocase ascii wide
                        $string32_powershell_offensive_tool_keyword = /New\-ItemProperty\s.{0,1000}\s\\"EnableScriptBlockLogging\\"\s\-PropertyType\sDWord\s\-Value\s0/ nocase ascii wide
                        $string33_powershell_offensive_tool_keyword = /powershell\.exe\s\-nop\s\-c\s\\"start\-job\s.{0,1000}Import\-Module\sBitsTransfer.{0,1000}\$env\:temp.{0,1000}GetRandomFileName\(\).{0,1000}Start\-BitsTransfer\s\-Source\s\'http.{0,1000}Remove\-Item.{0,1000}Receive\-Job/ nocase ascii wide
                        $string34_powershell_offensive_tool_keyword = /reg\sadd\s.{0,1000}\sEnableModuleLogging\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
                        $string35_powershell_offensive_tool_keyword = /reg\sadd\s.{0,1000}\sEnableScriptBlockLogging\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
                        $string36_powershell_offensive_tool_keyword = /Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath/ nocase ascii wide
                        $string37_powershell_offensive_tool_keyword = /Remove\-ItemProperty\s.{0,1000}HKLM\:\\SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,1000}\s\-Name\s.{0,1000}SD/ nocase ascii wide
                        $string38_powershell_offensive_tool_keyword = "Remove-Module -Name PsReadline" nocase ascii wide
                        $string39_powershell_offensive_tool_keyword = /rundll32\.exe\sC\:\\Users\\Public\\/ nocase ascii wide
                        $string40_powershell_offensive_tool_keyword = /rundll32\.exe\sC\:\\windows\\System32\\comsvcs\.dll\sMiniDump\s\(Get\-Process\slsass\)\.id/ nocase ascii wide
                        $string41_powershell_offensive_tool_keyword = /Set\-ItemProperty\s.{0,1000}\s\\"EnableModuleLogging\\"\s\-Value\s0/ nocase ascii wide
                        $string42_powershell_offensive_tool_keyword = /Set\-ItemProperty\s.{0,1000}\s\\"EnableScriptBlockLogging\\"\s\-Value\s0/ nocase ascii wide
                        $string43_powershell_offensive_tool_keyword = /Set\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\"\s\-Name\s\\"EnableModuleLogging\\"\s\-Value\s0/ nocase ascii wide
                        $string44_powershell_offensive_tool_keyword = /Set\-MpPreference\s\-ExclusionPath\s.{0,1000}\s\-DisableRealtimeMonitoring/ nocase ascii wide
                        $string45_powershell_offensive_tool_keyword = "Set-PSReadlineOption -HistorySaveStyle SaveNothing" nocase ascii wide
                        $string46_powershell_offensive_tool_keyword = "YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA==" nocase ascii wide

    condition:
        any of them
}