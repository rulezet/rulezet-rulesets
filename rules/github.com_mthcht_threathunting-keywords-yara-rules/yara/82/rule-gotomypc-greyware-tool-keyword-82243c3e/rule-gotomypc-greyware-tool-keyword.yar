rule rule_GoToMyPC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GoToMyPC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoToMyPC"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_GoToMyPC_greyware_tool_keyword = /\sDownloadServer\=https\:\/\/www\.gotomypc\.com\s/ nocase ascii wide
                        $string2_GoToMyPC_greyware_tool_keyword = /\sgotoopener\:\/\/launch\.getgo\.com\// nocase ascii wide
                        $string3_GoToMyPC_greyware_tool_keyword = /\sLoggingServer\=logging\.getgo\.com\sProxyHost\=/ nocase ascii wide
                        $string4_GoToMyPC_greyware_tool_keyword = /\\AppData\\Local\\GoToMyPC\\/ nocase ascii wide
                        $string5_GoToMyPC_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\gosetup\.exe/ nocase ascii wide
                        $string6_GoToMyPC_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\GoToOpener\.msi/ nocase ascii wide
                        $string7_GoToMyPC_greyware_tool_keyword = /\\Citrix\\GoToMyPc\\FileTransfer\\history/ nocase ascii wide
                        $string8_GoToMyPC_greyware_tool_keyword = /\\Citrix\\GoToMyPc\\GuestInvite/ nocase ascii wide
                        $string9_GoToMyPC_greyware_tool_keyword = /\\g2comm\.exe/ nocase ascii wide
                        $string10_GoToMyPC_greyware_tool_keyword = /\\g2fileh\.exe/ nocase ascii wide
                        $string11_GoToMyPC_greyware_tool_keyword = /\\g2host\.exe/ nocase ascii wide
                        $string12_GoToMyPC_greyware_tool_keyword = /\\g2mainh\.exe/ nocase ascii wide
                        $string13_GoToMyPC_greyware_tool_keyword = /\\g2printh\.exe/ nocase ascii wide
                        $string14_GoToMyPC_greyware_tool_keyword = /\\g2svc\.exe/ nocase ascii wide
                        $string15_GoToMyPC_greyware_tool_keyword = /\\goLoader\.exe/ nocase ascii wide
                        $string16_GoToMyPC_greyware_tool_keyword = /\\gosetup\[1\]\.exe/ nocase ascii wide
                        $string17_GoToMyPC_greyware_tool_keyword = /\\GoTo\sOpener\.exe/ nocase ascii wide
                        $string18_GoToMyPC_greyware_tool_keyword = /\\GoTo\\Logs\\goto\.log/ nocase ascii wide
                        $string19_GoToMyPC_greyware_tool_keyword = /\\gotomon\.dll/ nocase ascii wide
                        $string20_GoToMyPC_greyware_tool_keyword = /\\gotomon_x64\.dll/ nocase ascii wide
                        $string21_GoToMyPC_greyware_tool_keyword = /\\GoToMyPC\.cab/ nocase ascii wide
                        $string22_GoToMyPC_greyware_tool_keyword = /\\GoToMyPC\\.{0,1000}\\.{0,1000}\\g2ldr\.log/ nocase ascii wide
                        $string23_GoToMyPC_greyware_tool_keyword = /\\gotomypc\\g2pre\.exe/ nocase ascii wide
                        $string24_GoToMyPC_greyware_tool_keyword = /\\GoToMyPC\\g2svc\.exe/ nocase ascii wide
                        $string25_GoToMyPC_greyware_tool_keyword = /\\gotomypc_3944\.exe/ nocase ascii wide
                        $string26_GoToMyPC_greyware_tool_keyword = /\\GoToMyPCCrashHandler\.exe/ nocase ascii wide
                        $string27_GoToMyPC_greyware_tool_keyword = /\\GoToOpener\.log/ nocase ascii wide
                        $string28_GoToMyPC_greyware_tool_keyword = /\\GoToOpener\[1\]\.msi/ nocase ascii wide
                        $string29_GoToMyPC_greyware_tool_keyword = /\\ICON_ID_GOTOMYPC/ nocase ascii wide
                        $string30_GoToMyPC_greyware_tool_keyword = /\\Local\\Temp\\LogMeInLogs\\GoToOpenerMsi\\/ nocase ascii wide
                        $string31_GoToMyPC_greyware_tool_keyword = /\\LogMeInLogs\\GoToOpenerMsi/ nocase ascii wide
                        $string32_GoToMyPC_greyware_tool_keyword = /\\novaPDF11OEM\(x64\)\.msi/ nocase ascii wide
                        $string33_GoToMyPC_greyware_tool_keyword = /\\program\sfiles\s\(x86\)\\gotomypc\\g2tray\.exe/ nocase ascii wide
                        $string34_GoToMyPC_greyware_tool_keyword = /\\Programs\\GoToMyPC\.lnk/ nocase ascii wide
                        $string35_GoToMyPC_greyware_tool_keyword = /\\WOW6432Node\\Citrix\\GoToMyPc/ nocase ascii wide
                        $string36_GoToMyPC_greyware_tool_keyword = /\\x64\\monblanking\.sys/ nocase ascii wide
                        $string37_GoToMyPC_greyware_tool_keyword = "<Data>Installed GoToMyPC</Data>" nocase ascii wide
                        $string38_GoToMyPC_greyware_tool_keyword = /\=http\:\/\/www\.gotomypc\.com\/downloads\/viewer\s/ nocase ascii wide
                        $string39_GoToMyPC_greyware_tool_keyword = /api\-telemetry\.servers\.getgo\.com/ nocase ascii wide
                        $string40_GoToMyPC_greyware_tool_keyword = "ApplicationName'>GoTo Opener" nocase ascii wide
                        $string41_GoToMyPC_greyware_tool_keyword = "ApplicationName'>GoToMyPC Communications" nocase ascii wide
                        $string42_GoToMyPC_greyware_tool_keyword = "ApplicationName'>GoToMyPC Host Launcher" nocase ascii wide
                        $string43_GoToMyPC_greyware_tool_keyword = "ApplicationName'>GoToMyPC Viewer" nocase ascii wide
                        $string44_GoToMyPC_greyware_tool_keyword = "cf3de8f800852490f39fdacbe74627564494235f" nocase ascii wide
                        $string45_GoToMyPC_greyware_tool_keyword = /G2MScrUtil64\.exe.{0,1000}\/cr/ nocase ascii wide
                        $string46_GoToMyPC_greyware_tool_keyword = /g2mui\.exe.{0,1000}\/cr/ nocase ascii wide
                        $string47_GoToMyPC_greyware_tool_keyword = /GoTo\sMyPC\sInstaller\.exe/ nocase ascii wide
                        $string48_GoToMyPC_greyware_tool_keyword = /GOTO\sMYPC\sINSTALLER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string49_GoToMyPC_greyware_tool_keyword = /GoTo\sOpener\.exe\s/ nocase ascii wide
                        $string50_GoToMyPC_greyware_tool_keyword = /GOTO\sOPENER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string51_GoToMyPC_greyware_tool_keyword = /Goto\.exe.{0,1000}\?type\=crashpad\-handler/ nocase ascii wide
                        $string52_GoToMyPC_greyware_tool_keyword = /GoToMyPC_Installation\.log/ nocase ascii wide
                        $string53_GoToMyPC_greyware_tool_keyword = /GoToMyPC_Setup\.log/ nocase ascii wide
                        $string54_GoToMyPC_greyware_tool_keyword = /GoToMyPCSetup_x64\.msi/ nocase ascii wide
                        $string55_GoToMyPC_greyware_tool_keyword = /GoToScrUtils\.exe.{0,1000}\/cr/ nocase ascii wide
                        $string56_GoToMyPC_greyware_tool_keyword = /launcher\-rest\-new\.live\.corecollab\.ucc\-prod\.eva\.goto\.com/ nocase ascii wide
                        $string57_GoToMyPC_greyware_tool_keyword = /novaPDF11PrinterDriver\(x64\)\.msi/ nocase ascii wide
                        $string58_GoToMyPC_greyware_tool_keyword = /PollServer\spoll\.gotomypc\.com/ nocase ascii wide
                        $string59_GoToMyPC_greyware_tool_keyword = "ServiceName'>GoToMyPC" nocase ascii wide

    condition:
        any of them
}