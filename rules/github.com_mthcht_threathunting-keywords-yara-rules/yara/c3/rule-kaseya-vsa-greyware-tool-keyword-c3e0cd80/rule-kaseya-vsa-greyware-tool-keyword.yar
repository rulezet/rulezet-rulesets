rule rule_kaseya_VSA_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kaseya VSA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kaseya VSA"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_kaseya_VSA_greyware_tool_keyword = /\spcmontask\.exe/ nocase ascii wide
                        $string2_kaseya_VSA_greyware_tool_keyword = /\sRemoteDesktop\.exe/ nocase ascii wide
                        $string3_kaseya_VSA_greyware_tool_keyword = /\sVSAX_x64\.msi/ nocase ascii wide
                        $string4_kaseya_VSA_greyware_tool_keyword = /\.vsax\.net/ nocase ascii wide
                        $string5_kaseya_VSA_greyware_tool_keyword = /\/pcmontask\.exe/ nocase ascii wide
                        $string6_kaseya_VSA_greyware_tool_keyword = /\/RemoteDesktop\.exe/ nocase ascii wide
                        $string7_kaseya_VSA_greyware_tool_keyword = /\/VSAX_x64\.msi/ nocase ascii wide
                        $string8_kaseya_VSA_greyware_tool_keyword = /\/vsxrc\-clip\.exe/ nocase ascii wide
                        $string9_kaseya_VSA_greyware_tool_keyword = /\\AppData\\Roaming\\freerdp/ nocase ascii wide
                        $string10_kaseya_VSA_greyware_tool_keyword = /\\AppData\\Roaming\\VSA\sX/ nocase ascii wide
                        $string11_kaseya_VSA_greyware_tool_keyword = /\\CurrentControlSet\\Services\\VSAX/ nocase ascii wide
                        $string12_kaseya_VSA_greyware_tool_keyword = /\\Kaseya\\PC\sMonitor\\/ nocase ascii wide
                        $string13_kaseya_VSA_greyware_tool_keyword = /\\PC\sMonitor\\Addons/ nocase ascii wide
                        $string14_kaseya_VSA_greyware_tool_keyword = /\\pcmontask\.exe/ nocase ascii wide
                        $string15_kaseya_VSA_greyware_tool_keyword = /\\pcmupdate\.exe/ nocase ascii wide
                        $string16_kaseya_VSA_greyware_tool_keyword = /\\RemoteDesktop\.exe/ nocase ascii wide
                        $string17_kaseya_VSA_greyware_tool_keyword = /\\Services\\EventLog\\Application\\VSA\sX/ nocase ascii wide
                        $string18_kaseya_VSA_greyware_tool_keyword = /\\Services\\EventLog\\Application\\VSAX/ nocase ascii wide
                        $string19_kaseya_VSA_greyware_tool_keyword = /\\SOFTWARE\\Kaseya\\/ nocase ascii wide
                        $string20_kaseya_VSA_greyware_tool_keyword = /\\TaskCache\\Tree\\VSA\sXServiceCheck/ nocase ascii wide
                        $string21_kaseya_VSA_greyware_tool_keyword = /\\VSA\sX\sManager\.lnk/ nocase ascii wide
                        $string22_kaseya_VSA_greyware_tool_keyword = /\\VSA\sX\sRemote\sControl\.lnk/ nocase ascii wide
                        $string23_kaseya_VSA_greyware_tool_keyword = /\\VSA\sX\sRemote\sControl\\/ nocase ascii wide
                        $string24_kaseya_VSA_greyware_tool_keyword = /\\VSA\sX\\watchdog\.bat/ nocase ascii wide
                        $string25_kaseya_VSA_greyware_tool_keyword = /\\VSA\sXServiceCheck/ nocase ascii wide
                        $string26_kaseya_VSA_greyware_tool_keyword = /\\VSAX\\working/ nocase ascii wide
                        $string27_kaseya_VSA_greyware_tool_keyword = /\\VSAX_x64\.msi/ nocase ascii wide
                        $string28_kaseya_VSA_greyware_tool_keyword = /\\vsxrc\-clip\.exe/ nocase ascii wide
                        $string29_kaseya_VSA_greyware_tool_keyword = /KASEYA\sHOLDINGS\sINC\./ nocase ascii wide
                        $string30_kaseya_VSA_greyware_tool_keyword = /managedsupport\.kaseya\.net/ nocase ascii wide
                        $string31_kaseya_VSA_greyware_tool_keyword = /PCMonitorCfg\.dll/ nocase ascii wide
                        $string32_kaseya_VSA_greyware_tool_keyword = /PCMonitorClient\.dll/ nocase ascii wide
                        $string33_kaseya_VSA_greyware_tool_keyword = /PCMonitorEng\.dll/ nocase ascii wide
                        $string34_kaseya_VSA_greyware_tool_keyword = /PCMonitorManager\.exe/ nocase ascii wide
                        $string35_kaseya_VSA_greyware_tool_keyword = /PCMonitorManager\.exe/ nocase ascii wide
                        $string36_kaseya_VSA_greyware_tool_keyword = /PCMONITORMANAGER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string37_kaseya_VSA_greyware_tool_keyword = /PCMonitorSrv\.exe/ nocase ascii wide
                        $string38_kaseya_VSA_greyware_tool_keyword = /PCMonitorSrv\.exe/ nocase ascii wide
                        $string39_kaseya_VSA_greyware_tool_keyword = /PCMONITORSRV\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string40_kaseya_VSA_greyware_tool_keyword = /PCMonitorSrv\.InstallState/ nocase ascii wide
                        $string41_kaseya_VSA_greyware_tool_keyword = /PCMonitorTypes\.dll/ nocase ascii wide
                        $string42_kaseya_VSA_greyware_tool_keyword = /pcmontask\.exe\s/ nocase ascii wide
                        $string43_kaseya_VSA_greyware_tool_keyword = /PCMONTASK\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string44_kaseya_VSA_greyware_tool_keyword = /pcmrdp\-client\.dll/ nocase ascii wide
                        $string45_kaseya_VSA_greyware_tool_keyword = /Program\sFiles\\VSA\sX\\/ nocase ascii wide
                        $string46_kaseya_VSA_greyware_tool_keyword = /ProgramData\\Kaseya\\/ nocase ascii wide
                        $string47_kaseya_VSA_greyware_tool_keyword = /RemoteDesktop\.exe\s/ nocase ascii wide
                        $string48_kaseya_VSA_greyware_tool_keyword = /RemoteDesktop_x64\s\(1\)\.msi/ nocase ascii wide
                        $string49_kaseya_VSA_greyware_tool_keyword = /RemoteDesktop_x64\.msi/ nocase ascii wide
                        $string50_kaseya_VSA_greyware_tool_keyword = "SC  QUERYEX \"PC Monitor\"" nocase ascii wide
                        $string51_kaseya_VSA_greyware_tool_keyword = "SC  QUERYEX \"VSAX\"" nocase ascii wide
                        $string52_kaseya_VSA_greyware_tool_keyword = "'ServiceName'>VSA X</Data>" nocase ascii wide
                        $string53_kaseya_VSA_greyware_tool_keyword = "'ServiceName'>VSAX</Data>" nocase ascii wide
                        $string54_kaseya_VSA_greyware_tool_keyword = "'VSA X Manager" nocase ascii wide
                        $string55_kaseya_VSA_greyware_tool_keyword = "'VSA X Remote Control'" nocase ascii wide
                        $string56_kaseya_VSA_greyware_tool_keyword = "'VSA X Service'" nocase ascii wide
                        $string57_kaseya_VSA_greyware_tool_keyword = "'VSA X User Agent'" nocase ascii wide
                        $string58_kaseya_VSA_greyware_tool_keyword = /vsxrc\-client\.dll/ nocase ascii wide

    condition:
        any of them
}