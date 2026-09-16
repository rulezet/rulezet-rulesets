rule rule_Google_Remote_Desktop_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Google Remote Desktop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Google Remote Desktop"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Google_Remote_Desktop_greyware_tool_keyword = " chrome-remote-desktop@" nocase ascii wide
                        $string2_Google_Remote_Desktop_greyware_tool_keyword = /\.chrome\-remote\-desktop\-session/ nocase ascii wide
                        $string3_Google_Remote_Desktop_greyware_tool_keyword = "/system/chrome-remote-desktop@"
                        $string4_Google_Remote_Desktop_greyware_tool_keyword = /\\Chrome\sRemote\sDesktop\\host\.json/ nocase ascii wide
                        $string5_Google_Remote_Desktop_greyware_tool_keyword = /\\Google\\Chrome\sRemote\sDesktop\\/ nocase ascii wide
                        $string6_Google_Remote_Desktop_greyware_tool_keyword = /\\pipe\\chrome_remote_desktop/ nocase ascii wide
                        $string7_Google_Remote_Desktop_greyware_tool_keyword = /\\remote_assistance_host\.exe/ nocase ascii wide
                        $string8_Google_Remote_Desktop_greyware_tool_keyword = /\\remoting_desktop\.exe/ nocase ascii wide
                        $string9_Google_Remote_Desktop_greyware_tool_keyword = /\\remoting_host\.exe/ nocase ascii wide
                        $string10_Google_Remote_Desktop_greyware_tool_keyword = /\\remoting_native_messaging_host\.exe/ nocase ascii wide
                        $string11_Google_Remote_Desktop_greyware_tool_keyword = /\\remoting_start_host\.exe/ nocase ascii wide
                        $string12_Google_Remote_Desktop_greyware_tool_keyword = "<Data>Product: Chrome Remote Desktop Host" nocase ascii wide
                        $string13_Google_Remote_Desktop_greyware_tool_keyword = "<Provider Name=\"chromoting\" />" nocase ascii wide
                        $string14_Google_Remote_Desktop_greyware_tool_keyword = /Channel\sIP\sfor\sclient\:\s.{0,100}\@gmail\.com\/chromoting/ nocase ascii wide
                        $string15_Google_Remote_Desktop_greyware_tool_keyword = "Chrome remote desktop installation completed" nocase ascii wide
                        $string16_Google_Remote_Desktop_greyware_tool_keyword = /chrome\-remote\-desktop\.service/ nocase ascii wide
                        $string17_Google_Remote_Desktop_greyware_tool_keyword = /chrome\-remote\-desktop_current_amd64\.deb/ nocase ascii wide
                        $string18_Google_Remote_Desktop_greyware_tool_keyword = /chromeremotedesktophost\.msi/ nocase ascii wide
                        $string19_Google_Remote_Desktop_greyware_tool_keyword = "export CHROME_REMOTE_DESKTOP_DEFAULT_DESKTOP_SIZES" nocase ascii wide
                        $string20_Google_Remote_Desktop_greyware_tool_keyword = "-Force Stop-Process -Name remote_webauthn" nocase ascii wide
                        $string21_Google_Remote_Desktop_greyware_tool_keyword = /google\-chrome\-stable_current_amd64\.deb/ nocase ascii wide
                        $string22_Google_Remote_Desktop_greyware_tool_keyword = /https\:\/\/remotedesktop\.google\.com\/_\/oauthredirect/ nocase ascii wide
                        $string23_Google_Remote_Desktop_greyware_tool_keyword = /https\:\/\/remotedesktop\.google\.com\/headless/ nocase ascii wide
                        $string24_Google_Remote_Desktop_greyware_tool_keyword = "inomeogfingihgjfjlpeplalcfajhgai" nocase ascii wide
                        $string25_Google_Remote_Desktop_greyware_tool_keyword = /remotedesktop\.google\.com\/access/ nocase ascii wide
                        $string26_Google_Remote_Desktop_greyware_tool_keyword = /remotedesktop\.google\.com\/support/ nocase ascii wide
                        $string27_Google_Remote_Desktop_greyware_tool_keyword = "Stop-Process -Force -Name remote_assistance_host" nocase ascii wide
                        $string28_Google_Remote_Desktop_greyware_tool_keyword = "Stop-Process -Force -Name remote_assistance_host_uiaccess" nocase ascii wide
                        $string29_Google_Remote_Desktop_greyware_tool_keyword = "Stop-Process -Force -Name remoting_native_messaging_host" nocase ascii wide
                        $string30_Google_Remote_Desktop_greyware_tool_keyword = "SYSLOG_IDENTIFIER=chrome-remote-desktop" nocase ascii wide
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