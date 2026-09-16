rule kaseya_VSA
{
    meta:
        description = "Detection patterns for the tool 'kaseya VSA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kaseya VSA"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\spcmontask\.exe/ nocase ascii wide
                        $string2 = /\sRemoteDesktop\.exe/ nocase ascii wide
                        $string3 = /\sVSAX_x64\.msi/ nocase ascii wide
                        $string4 = /\.vsax\.net/ nocase ascii wide
                        $string5 = /\/pcmontask\.exe/ nocase ascii wide
                        $string6 = /\/RemoteDesktop\.exe/ nocase ascii wide
                        $string7 = /\/VSAX_x64\.msi/ nocase ascii wide
                        $string8 = /\/vsxrc\-clip\.exe/ nocase ascii wide
                        $string9 = /\\AppData\\Roaming\\freerdp/ nocase ascii wide
                        $string10 = /\\AppData\\Roaming\\VSA\sX/ nocase ascii wide
                        $string11 = /\\CurrentControlSet\\Services\\VSAX/ nocase ascii wide
                        $string12 = /\\Kaseya\\PC\sMonitor\\/ nocase ascii wide
                        $string13 = /\\PC\sMonitor\\Addons/ nocase ascii wide
                        $string14 = /\\pcmontask\.exe/ nocase ascii wide
                        $string15 = /\\pcmupdate\.exe/ nocase ascii wide
                        $string16 = /\\RemoteDesktop\.exe/ nocase ascii wide
                        $string17 = /\\Services\\EventLog\\Application\\VSA\sX/ nocase ascii wide
                        $string18 = /\\Services\\EventLog\\Application\\VSAX/ nocase ascii wide
                        $string19 = /\\SOFTWARE\\Kaseya\\/ nocase ascii wide
                        $string20 = /\\TaskCache\\Tree\\VSA\sXServiceCheck/ nocase ascii wide
                        $string21 = /\\VSA\sX\sManager\.lnk/ nocase ascii wide
                        $string22 = /\\VSA\sX\sRemote\sControl\.lnk/ nocase ascii wide
                        $string23 = /\\VSA\sX\sRemote\sControl\\/ nocase ascii wide
                        $string24 = /\\VSA\sX\\watchdog\.bat/ nocase ascii wide
                        $string25 = /\\VSA\sXServiceCheck/ nocase ascii wide
                        $string26 = /\\VSAX\\working/ nocase ascii wide
                        $string27 = /\\VSAX_x64\.msi/ nocase ascii wide
                        $string28 = /\\vsxrc\-clip\.exe/ nocase ascii wide
                        $string29 = /KASEYA\sHOLDINGS\sINC\./ nocase ascii wide
                        $string30 = /managedsupport\.kaseya\.net/ nocase ascii wide
                        $string31 = /PCMonitorCfg\.dll/ nocase ascii wide
                        $string32 = /PCMonitorClient\.dll/ nocase ascii wide
                        $string33 = /PCMonitorEng\.dll/ nocase ascii wide
                        $string34 = /PCMonitorManager\.exe/ nocase ascii wide
                        $string35 = /PCMonitorManager\.exe/ nocase ascii wide
                        $string36 = /PCMONITORMANAGER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string37 = /PCMonitorSrv\.exe/ nocase ascii wide
                        $string38 = /PCMonitorSrv\.exe/ nocase ascii wide
                        $string39 = /PCMONITORSRV\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string40 = /PCMonitorSrv\.InstallState/ nocase ascii wide
                        $string41 = /PCMonitorTypes\.dll/ nocase ascii wide
                        $string42 = /pcmontask\.exe\s/ nocase ascii wide
                        $string43 = /PCMONTASK\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string44 = /pcmrdp\-client\.dll/ nocase ascii wide
                        $string45 = /Program\sFiles\\VSA\sX\\/ nocase ascii wide
                        $string46 = /ProgramData\\Kaseya\\/ nocase ascii wide
                        $string47 = /RemoteDesktop\.exe\s/ nocase ascii wide
                        $string48 = /RemoteDesktop_x64\s\(1\)\.msi/ nocase ascii wide
                        $string49 = /RemoteDesktop_x64\.msi/ nocase ascii wide
                        $string50 = "SC  QUERYEX \"PC Monitor\"" nocase ascii wide
                        $string51 = "SC  QUERYEX \"VSAX\"" nocase ascii wide
                        $string52 = "'ServiceName'>VSA X</Data>" nocase ascii wide
                        $string53 = "'ServiceName'>VSAX</Data>" nocase ascii wide
                        $string54 = "'VSA X Manager" nocase ascii wide
                        $string55 = "'VSA X Remote Control'" nocase ascii wide
                        $string56 = "'VSA X Service'" nocase ascii wide
                        $string57 = "'VSA X User Agent'" nocase ascii wide
                        $string58 = /vsxrc\-client\.dll/ nocase ascii wide

    condition:
        any of them
}