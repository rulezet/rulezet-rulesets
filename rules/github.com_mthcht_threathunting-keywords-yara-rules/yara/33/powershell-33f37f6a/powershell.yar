rule powershell
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " imaohw" nocase ascii wide
                        $string2 = " resu ten" nocase ascii wide
                        $string3 = "//:ptth" nocase ascii wide
                        $string4 = "//:sptth" nocase ascii wide
                        $string5 = /\[Reflection\.Assembly\]\:\:LoadWithPartialName\(\'System\.Core\'\)\.GetType\(\'System\.Diagnostics\.Eventing\.EventProvider\'\)\.GetField\(\'m_enabled\'.{0,1000}\'NonPublic.{0,1000}Instance\'\)\.SetValue\(\[Ref\]\.Assembly\.GetType\(\'System\.Management\.Automation\.Tracing\.PSEtwLogProvider\'\)\.GetField\(\'etwProvider\'.{0,1000}\'NonPublic.{0,1000}Static\'\)\.GetValue\(\$null\).{0,1000}0\)/ nocase ascii wide
                        $string6 = /\\\:MLKH/ nocase ascii wide
                        $string7 = /\\\\\:C/ nocase ascii wide
                        $string8 = /\\\\ataDmargorP\\\\\:C/ nocase ascii wide
                        $string9 = /\\\\swodniW\\\\\:C/ nocase ascii wide
                        $string10 = /\\ataDmargorP\\\:C/ nocase ascii wide
                        $string11 = /\\erawtfoS\\UCKH/ nocase ascii wide
                        $string12 = /\\swodniW\\\:C/ nocase ascii wide
                        $string13 = "=imaohw" nocase ascii wide
                        $string14 = "=resu ten" nocase ascii wide
                        $string15 = "Add-MpPreference -DisableBehaviorMonitoring True" nocase ascii wide
                        $string16 = "Add-MpPreference -DisableBehaviourMonitoring True" nocase ascii wide
                        $string17 = "Add-MpPreference -DisDisableRealtimeMonitoring True" nocase ascii wide
                        $string18 = "Add-MpPreference -ExclusionPath " nocase ascii wide
                        $string19 = /Add\-MpPreference\s\-ExclustionPath\sc\:\\users\\public/ nocase ascii wide
                        $string20 = /azuread_decrypt_msol_.{0,1000}\.ps1/ nocase ascii wide
                        $string21 = /cilbuP\\\\sresU\\\\\:C/ nocase ascii wide
                        $string22 = /cilbuP\\sresU\\\:C/ nocase ascii wide
                        $string23 = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C\s.{0,1000}\\temp/ nocase ascii wide
                        $string24 = /Get\-ADComputer\s.{0,1000}\s\-Properties\sPrincipalsAllowedToDelegateToAccount/ nocase ascii wide
                        $string25 = /Get\-Cluster\|Set\-Cluster\s\-HAEnabled\:\$false\s\-DrsEnabled\:\$false/ nocase ascii wide
                        $string26 = /http\:\/\/.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string27 = /https\:\/\/.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string28 = /Import\-Module\s.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string29 = "Invoke-SDPropagator" nocase ascii wide
                        $string30 = "llehsrewop" nocase ascii wide
                        $string31 = /New\-ItemProperty\s.{0,1000}\s\\"EnableModuleLogging\\"\s\-PropertyType\sDWord\s\-Value\s0/ nocase ascii wide
                        $string32 = /New\-ItemProperty\s.{0,1000}\s\\"EnableScriptBlockLogging\\"\s\-PropertyType\sDWord\s\-Value\s0/ nocase ascii wide
                        $string33 = /powershell\.exe\s\-nop\s\-c\s\\"start\-job\s.{0,1000}Import\-Module\sBitsTransfer.{0,1000}\$env\:temp.{0,1000}GetRandomFileName\(\).{0,1000}Start\-BitsTransfer\s\-Source\s\'http.{0,1000}Remove\-Item.{0,1000}Receive\-Job/ nocase ascii wide
                        $string34 = /reg\sadd\s.{0,1000}\sEnableModuleLogging\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
                        $string35 = /reg\sadd\s.{0,1000}\sEnableScriptBlockLogging\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
                        $string36 = /Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath/ nocase ascii wide
                        $string37 = /Remove\-ItemProperty\s.{0,1000}HKLM\:\\SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,1000}\s\-Name\s.{0,1000}SD/ nocase ascii wide
                        $string38 = "Remove-Module -Name PsReadline" nocase ascii wide
                        $string39 = /rundll32\.exe\sC\:\\Users\\Public\\/ nocase ascii wide
                        $string40 = /rundll32\.exe\sC\:\\windows\\System32\\comsvcs\.dll\sMiniDump\s\(Get\-Process\slsass\)\.id/ nocase ascii wide
                        $string41 = /Set\-ItemProperty\s.{0,1000}\s\\"EnableModuleLogging\\"\s\-Value\s0/ nocase ascii wide
                        $string42 = /Set\-ItemProperty\s.{0,1000}\s\\"EnableScriptBlockLogging\\"\s\-Value\s0/ nocase ascii wide
                        $string43 = /Set\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\"\s\-Name\s\\"EnableModuleLogging\\"\s\-Value\s0/ nocase ascii wide
                        $string44 = /Set\-MpPreference\s\-ExclusionPath\s.{0,1000}\s\-DisableRealtimeMonitoring/ nocase ascii wide
                        $string45 = "Set-PSReadlineOption -HistorySaveStyle SaveNothing" nocase ascii wide
                        $string46 = "YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA==" nocase ascii wide

    condition:
        any of them
}