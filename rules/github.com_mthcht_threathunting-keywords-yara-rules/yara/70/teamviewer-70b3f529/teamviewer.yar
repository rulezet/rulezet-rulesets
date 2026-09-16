rule teamviewer
{
    meta:
        description = "Detection patterns for the tool 'teamviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamviewer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-\-IPCport\s5939\s\-\-Module\s1/ nocase ascii wide
                        $string2 = /\.router\.teamviewer\.com/ nocase ascii wide
                        $string3 = "/Create /TN TVInstallRestore /TR " nocase ascii wide
                        $string4 = /\\AppData\\Roaming\\TeamViewer/ nocase ascii wide
                        $string5 = /\\CurrentControlSet\\Services\\TeamViewer/ nocase ascii wide
                        $string6 = /\\Program\sFiles\\TeamViewer/ nocase ascii wide
                        $string7 = /\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
                        $string8 = /\\Services\\TeamViewer\\/ nocase ascii wide
                        $string9 = /\\Software\\TeamViewer\\Temp/ nocase ascii wide
                        $string10 = /\\TeamViewer\.exe/ nocase ascii wide
                        $string11 = /\\TeamViewer\\Connections\.txt/ nocase ascii wide
                        $string12 = /\\TeamViewer\\Connections_incoming\.txt/ nocase ascii wide
                        $string13 = /\\TeamViewer_\.ex/ nocase ascii wide
                        $string14 = /\\teamviewer_note\.exe/ nocase ascii wide
                        $string15 = /\\TeamViewerSession\\shell\\open/ nocase ascii wide
                        $string16 = /\\TeamViewerTermsOfUseAccepted/ nocase ascii wide
                        $string17 = /\\TV15Install\.log/ nocase ascii wide
                        $string18 = /\\TVExtractTemp\\TeamViewer_Resource_/ nocase ascii wide
                        $string19 = /\\TVExtractTemp\\tvfiles\.7z/ nocase ascii wide
                        $string20 = /\\TvGetVersion\.dll/ nocase ascii wide
                        $string21 = /\\TVNetwork\.log/ nocase ascii wide
                        $string22 = /\\TVWebRTC\.dll/ nocase ascii wide
                        $string23 = /\\Users\\Public\\Desktop\\TVTest\.tmp/ nocase ascii wide
                        $string24 = /\\Windows\\Temp\\TeamViewer/ nocase ascii wide
                        $string25 = /AppData\\Local\\Temp\\TeamViewer/ nocase ascii wide
                        $string26 = /AppData\\Roaming\\Microsoft\\Windows\\SendTo\\TeamViewer\.lnk/ nocase ascii wide
                        $string27 = /client\.teamviewer\.com/ nocase ascii wide
                        $string28 = /download\.teamviewer\.com\.cdn\.cloudflare\.net/ nocase ascii wide
                        $string29 = /HKLM\\SOFTWARE\\TeamViewer/ nocase ascii wide
                        $string30 = /MRU\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
                        $string31 = /taf\.teamviewer\.com/ nocase ascii wide
                        $string32 = "TeamViewer VPN Adapter" nocase ascii wide
                        $string33 = /TEAMVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string34 = /TeamViewer\\tv_w32\.exe/ nocase ascii wide
                        $string35 = /TeamViewer\\tv_x64\.dll/ nocase ascii wide
                        $string36 = /TeamViewer\\tv_x64\.exe/ nocase ascii wide
                        $string37 = /TeamViewer\\TVNetwork\.log/ nocase ascii wide
                        $string38 = /TEAMVIEWER_\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string39 = /TeamViewer_Desktop\.exe/ nocase ascii wide
                        $string40 = /TEAMVIEWER_DESKTOP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string41 = /TeamViewer_Hooks\.log/ nocase ascii wide
                        $string42 = "TeamViewer_LogMutex" nocase ascii wide
                        $string43 = /TeamViewer_Service\.exe/ nocase ascii wide
                        $string44 = /TEAMVIEWER_SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string45 = /TeamViewer_Setup_x64\.exe/ nocase ascii wide
                        $string46 = /TEAMVIEWER_SETUP_X64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string47 = "TeamViewer_VirtualDeviceDriver" nocase ascii wide
                        $string48 = "TeamViewer_XPSDriverFilter" nocase ascii wide
                        $string49 = /TeamViewer15_Logfile\.log/ nocase ascii wide
                        $string50 = "TeamViewer3_Win32_Instance_Mutex" nocase ascii wide
                        $string51 = "TeamViewerHooks_DynamicMemMutex" nocase ascii wide
                        $string52 = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide
                        $string53 = /TeamViewerMeetingAddinShim\.dll/ nocase ascii wide
                        $string54 = /TeamViewerMeetingAddinShim64\.dll/ nocase ascii wide
                        $string55 = /teamviewervpn\.sys/ nocase ascii wide

    condition:
        any of them
}