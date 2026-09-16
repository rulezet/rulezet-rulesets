rule GoToMyPC
{
    meta:
        description = "Detection patterns for the tool 'GoToMyPC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoToMyPC"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sDownloadServer\=https\:\/\/www\.gotomypc\.com\s/ nocase ascii wide
                        $string2 = /\sgotoopener\:\/\/launch\.getgo\.com\// nocase ascii wide
                        $string3 = /\sLoggingServer\=logging\.getgo\.com\sProxyHost\=/ nocase ascii wide
                        $string4 = /\\AppData\\Local\\GoToMyPC\\/ nocase ascii wide
                        $string5 = /\\AppData\\Local\\Temp\\.{0,1000}\\gosetup\.exe/ nocase ascii wide
                        $string6 = /\\AppData\\Local\\Temp\\.{0,1000}\\GoToOpener\.msi/ nocase ascii wide
                        $string7 = /\\Citrix\\GoToMyPc\\FileTransfer\\history/ nocase ascii wide
                        $string8 = /\\Citrix\\GoToMyPc\\GuestInvite/ nocase ascii wide
                        $string9 = /\\g2comm\.exe/ nocase ascii wide
                        $string10 = /\\g2fileh\.exe/ nocase ascii wide
                        $string11 = /\\g2host\.exe/ nocase ascii wide
                        $string12 = /\\g2mainh\.exe/ nocase ascii wide
                        $string13 = /\\g2printh\.exe/ nocase ascii wide
                        $string14 = /\\g2svc\.exe/ nocase ascii wide
                        $string15 = /\\goLoader\.exe/ nocase ascii wide
                        $string16 = /\\gosetup\[1\]\.exe/ nocase ascii wide
                        $string17 = /\\GoTo\sOpener\.exe/ nocase ascii wide
                        $string18 = /\\GoTo\\Logs\\goto\.log/ nocase ascii wide
                        $string19 = /\\gotomon\.dll/ nocase ascii wide
                        $string20 = /\\gotomon_x64\.dll/ nocase ascii wide
                        $string21 = /\\GoToMyPC\.cab/ nocase ascii wide
                        $string22 = /\\GoToMyPC\\.{0,1000}\\.{0,1000}\\g2ldr\.log/ nocase ascii wide
                        $string23 = /\\gotomypc\\g2pre\.exe/ nocase ascii wide
                        $string24 = /\\GoToMyPC\\g2svc\.exe/ nocase ascii wide
                        $string25 = /\\gotomypc_3944\.exe/ nocase ascii wide
                        $string26 = /\\GoToMyPCCrashHandler\.exe/ nocase ascii wide
                        $string27 = /\\GoToOpener\.log/ nocase ascii wide
                        $string28 = /\\GoToOpener\[1\]\.msi/ nocase ascii wide
                        $string29 = /\\ICON_ID_GOTOMYPC/ nocase ascii wide
                        $string30 = /\\Local\\Temp\\LogMeInLogs\\GoToOpenerMsi\\/ nocase ascii wide
                        $string31 = /\\LogMeInLogs\\GoToOpenerMsi/ nocase ascii wide
                        $string32 = /\\novaPDF11OEM\(x64\)\.msi/ nocase ascii wide
                        $string33 = /\\program\sfiles\s\(x86\)\\gotomypc\\g2tray\.exe/ nocase ascii wide
                        $string34 = /\\Programs\\GoToMyPC\.lnk/ nocase ascii wide
                        $string35 = /\\WOW6432Node\\Citrix\\GoToMyPc/ nocase ascii wide
                        $string36 = /\\x64\\monblanking\.sys/ nocase ascii wide
                        $string37 = "<Data>Installed GoToMyPC</Data>" nocase ascii wide
                        $string38 = /\=http\:\/\/www\.gotomypc\.com\/downloads\/viewer\s/ nocase ascii wide
                        $string39 = /api\-telemetry\.servers\.getgo\.com/ nocase ascii wide
                        $string40 = "ApplicationName'>GoTo Opener" nocase ascii wide
                        $string41 = "ApplicationName'>GoToMyPC Communications" nocase ascii wide
                        $string42 = "ApplicationName'>GoToMyPC Host Launcher" nocase ascii wide
                        $string43 = "ApplicationName'>GoToMyPC Viewer" nocase ascii wide
                        $string44 = "cf3de8f800852490f39fdacbe74627564494235f" nocase ascii wide
                        $string45 = /G2MScrUtil64\.exe.{0,1000}\/cr/ nocase ascii wide
                        $string46 = /g2mui\.exe.{0,1000}\/cr/ nocase ascii wide
                        $string47 = /GoTo\sMyPC\sInstaller\.exe/ nocase ascii wide
                        $string48 = /GOTO\sMYPC\sINSTALLER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string49 = /GoTo\sOpener\.exe\s/ nocase ascii wide
                        $string50 = /GOTO\sOPENER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string51 = /Goto\.exe.{0,1000}\?type\=crashpad\-handler/ nocase ascii wide
                        $string52 = /GoToMyPC_Installation\.log/ nocase ascii wide
                        $string53 = /GoToMyPC_Setup\.log/ nocase ascii wide
                        $string54 = /GoToMyPCSetup_x64\.msi/ nocase ascii wide
                        $string55 = /GoToScrUtils\.exe.{0,1000}\/cr/ nocase ascii wide
                        $string56 = /launcher\-rest\-new\.live\.corecollab\.ucc\-prod\.eva\.goto\.com/ nocase ascii wide
                        $string57 = /novaPDF11PrinterDriver\(x64\)\.msi/ nocase ascii wide
                        $string58 = /PollServer\spoll\.gotomypc\.com/ nocase ascii wide
                        $string59 = "ServiceName'>GoToMyPC" nocase ascii wide

    condition:
        any of them
}