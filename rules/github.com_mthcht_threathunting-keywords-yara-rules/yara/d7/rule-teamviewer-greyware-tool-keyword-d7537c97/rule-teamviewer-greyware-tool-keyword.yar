rule rule_teamviewer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'teamviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamviewer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_teamviewer_greyware_tool_keyword = /\.exe\s\-\-IPCport\s5939\s\-\-Module\s1/ nocase ascii wide
                        $string2_teamviewer_greyware_tool_keyword = /\.router\.teamviewer\.com/ nocase ascii wide
                        $string3_teamviewer_greyware_tool_keyword = "/Create /TN TVInstallRestore /TR " nocase ascii wide
                        $string4_teamviewer_greyware_tool_keyword = /\\AppData\\Roaming\\TeamViewer/ nocase ascii wide
                        $string5_teamviewer_greyware_tool_keyword = /\\CurrentControlSet\\Services\\TeamViewer/ nocase ascii wide
                        $string6_teamviewer_greyware_tool_keyword = /\\Program\sFiles\\TeamViewer/ nocase ascii wide
                        $string7_teamviewer_greyware_tool_keyword = /\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
                        $string8_teamviewer_greyware_tool_keyword = /\\Services\\TeamViewer\\/ nocase ascii wide
                        $string9_teamviewer_greyware_tool_keyword = /\\Software\\TeamViewer\\Temp/ nocase ascii wide
                        $string10_teamviewer_greyware_tool_keyword = /\\TeamViewer\.exe/ nocase ascii wide
                        $string11_teamviewer_greyware_tool_keyword = /\\TeamViewer\\Connections\.txt/ nocase ascii wide
                        $string12_teamviewer_greyware_tool_keyword = /\\TeamViewer\\Connections_incoming\.txt/ nocase ascii wide
                        $string13_teamviewer_greyware_tool_keyword = /\\TeamViewer_\.ex/ nocase ascii wide
                        $string14_teamviewer_greyware_tool_keyword = /\\teamviewer_note\.exe/ nocase ascii wide
                        $string15_teamviewer_greyware_tool_keyword = /\\TeamViewerSession\\shell\\open/ nocase ascii wide
                        $string16_teamviewer_greyware_tool_keyword = /\\TeamViewerTermsOfUseAccepted/ nocase ascii wide
                        $string17_teamviewer_greyware_tool_keyword = /\\TV15Install\.log/ nocase ascii wide
                        $string18_teamviewer_greyware_tool_keyword = /\\TVExtractTemp\\TeamViewer_Resource_/ nocase ascii wide
                        $string19_teamviewer_greyware_tool_keyword = /\\TVExtractTemp\\tvfiles\.7z/ nocase ascii wide
                        $string20_teamviewer_greyware_tool_keyword = /\\TvGetVersion\.dll/ nocase ascii wide
                        $string21_teamviewer_greyware_tool_keyword = /\\TVNetwork\.log/ nocase ascii wide
                        $string22_teamviewer_greyware_tool_keyword = /\\TVWebRTC\.dll/ nocase ascii wide
                        $string23_teamviewer_greyware_tool_keyword = /\\Users\\Public\\Desktop\\TVTest\.tmp/ nocase ascii wide
                        $string24_teamviewer_greyware_tool_keyword = /\\Windows\\Temp\\TeamViewer/ nocase ascii wide
                        $string25_teamviewer_greyware_tool_keyword = /AppData\\Local\\Temp\\TeamViewer/ nocase ascii wide
                        $string26_teamviewer_greyware_tool_keyword = /AppData\\Roaming\\Microsoft\\Windows\\SendTo\\TeamViewer\.lnk/ nocase ascii wide
                        $string27_teamviewer_greyware_tool_keyword = /client\.teamviewer\.com/ nocase ascii wide
                        $string28_teamviewer_greyware_tool_keyword = /download\.teamviewer\.com\.cdn\.cloudflare\.net/ nocase ascii wide
                        $string29_teamviewer_greyware_tool_keyword = /HKLM\\SOFTWARE\\TeamViewer/ nocase ascii wide
                        $string30_teamviewer_greyware_tool_keyword = /MRU\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
                        $string31_teamviewer_greyware_tool_keyword = /taf\.teamviewer\.com/ nocase ascii wide
                        $string32_teamviewer_greyware_tool_keyword = "TeamViewer VPN Adapter" nocase ascii wide
                        $string33_teamviewer_greyware_tool_keyword = /TEAMVIEWER\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string34_teamviewer_greyware_tool_keyword = /TeamViewer\\tv_w32\.exe/ nocase ascii wide
                        $string35_teamviewer_greyware_tool_keyword = /TeamViewer\\tv_x64\.dll/ nocase ascii wide
                        $string36_teamviewer_greyware_tool_keyword = /TeamViewer\\tv_x64\.exe/ nocase ascii wide
                        $string37_teamviewer_greyware_tool_keyword = /TeamViewer\\TVNetwork\.log/ nocase ascii wide
                        $string38_teamviewer_greyware_tool_keyword = /TEAMVIEWER_\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string39_teamviewer_greyware_tool_keyword = /TeamViewer_Desktop\.exe/ nocase ascii wide
                        $string40_teamviewer_greyware_tool_keyword = /TEAMVIEWER_DESKTOP\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string41_teamviewer_greyware_tool_keyword = /TeamViewer_Hooks\.log/ nocase ascii wide
                        $string42_teamviewer_greyware_tool_keyword = "TeamViewer_LogMutex" nocase ascii wide
                        $string43_teamviewer_greyware_tool_keyword = /TeamViewer_Service\.exe/ nocase ascii wide
                        $string44_teamviewer_greyware_tool_keyword = /TEAMVIEWER_SERVICE\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string45_teamviewer_greyware_tool_keyword = /TeamViewer_Setup_x64\.exe/ nocase ascii wide
                        $string46_teamviewer_greyware_tool_keyword = /TEAMVIEWER_SETUP_X64\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string47_teamviewer_greyware_tool_keyword = "TeamViewer_VirtualDeviceDriver" nocase ascii wide
                        $string48_teamviewer_greyware_tool_keyword = "TeamViewer_XPSDriverFilter" nocase ascii wide
                        $string49_teamviewer_greyware_tool_keyword = /TeamViewer15_Logfile\.log/ nocase ascii wide
                        $string50_teamviewer_greyware_tool_keyword = "TeamViewer3_Win32_Instance_Mutex" nocase ascii wide
                        $string51_teamviewer_greyware_tool_keyword = "TeamViewerHooks_DynamicMemMutex" nocase ascii wide
                        $string52_teamviewer_greyware_tool_keyword = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide
                        $string53_teamviewer_greyware_tool_keyword = /TeamViewerMeetingAddinShim\.dll/ nocase ascii wide
                        $string54_teamviewer_greyware_tool_keyword = /TeamViewerMeetingAddinShim64\.dll/ nocase ascii wide
                        $string55_teamviewer_greyware_tool_keyword = /teamviewervpn\.sys/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}