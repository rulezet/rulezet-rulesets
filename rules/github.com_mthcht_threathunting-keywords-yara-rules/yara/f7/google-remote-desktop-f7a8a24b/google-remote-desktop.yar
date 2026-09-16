rule Google_Remote_Desktop
{
    meta:
        description = "Detection patterns for the tool 'Google Remote Desktop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Google Remote Desktop"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " chrome-remote-desktop@" nocase ascii wide
                        $string2 = /\.chrome\-remote\-desktop\-session/ nocase ascii wide
                        $string3 = "/system/chrome-remote-desktop@"
                        $string4 = /\\Chrome\sRemote\sDesktop\\host\.json/ nocase ascii wide
                        $string5 = /\\Google\\Chrome\sRemote\sDesktop\\/ nocase ascii wide
                        $string6 = /\\pipe\\chrome_remote_desktop/ nocase ascii wide
                        $string7 = /\\remote_assistance_host\.exe/ nocase ascii wide
                        $string8 = /\\remoting_desktop\.exe/ nocase ascii wide
                        $string9 = /\\remoting_host\.exe/ nocase ascii wide
                        $string10 = /\\remoting_native_messaging_host\.exe/ nocase ascii wide
                        $string11 = /\\remoting_start_host\.exe/ nocase ascii wide
                        $string12 = "<Data>Product: Chrome Remote Desktop Host" nocase ascii wide
                        $string13 = "<Provider Name=\"chromoting\" />" nocase ascii wide
                        $string14 = /Channel\sIP\sfor\sclient\:\s.{0,100}\@gmail\.com\/chromoting/ nocase ascii wide
                        $string15 = "Chrome remote desktop installation completed" nocase ascii wide
                        $string16 = /chrome\-remote\-desktop\.service/ nocase ascii wide
                        $string17 = /chrome\-remote\-desktop_current_amd64\.deb/ nocase ascii wide
                        $string18 = /chromeremotedesktophost\.msi/ nocase ascii wide
                        $string19 = "export CHROME_REMOTE_DESKTOP_DEFAULT_DESKTOP_SIZES" nocase ascii wide
                        $string20 = "-Force Stop-Process -Name remote_webauthn" nocase ascii wide
                        $string21 = /google\-chrome\-stable_current_amd64\.deb/ nocase ascii wide
                        $string22 = /https\:\/\/remotedesktop\.google\.com\/_\/oauthredirect/ nocase ascii wide
                        $string23 = /https\:\/\/remotedesktop\.google\.com\/headless/ nocase ascii wide
                        $string24 = "inomeogfingihgjfjlpeplalcfajhgai" nocase ascii wide
                        $string25 = /remotedesktop\.google\.com\/access/ nocase ascii wide
                        $string26 = /remotedesktop\.google\.com\/support/ nocase ascii wide
                        $string27 = "Stop-Process -Force -Name remote_assistance_host" nocase ascii wide
                        $string28 = "Stop-Process -Force -Name remote_assistance_host_uiaccess" nocase ascii wide
                        $string29 = "Stop-Process -Force -Name remoting_native_messaging_host" nocase ascii wide
                        $string30 = "SYSLOG_IDENTIFIER=chrome-remote-desktop" nocase ascii wide
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