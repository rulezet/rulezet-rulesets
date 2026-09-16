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
                        $string14_Google_Remote_Desktop_greyware_tool_keyword = /Channel\sIP\sfor\sclient\:\s.{0,1000}\@gmail\.com\/chromoting/ nocase ascii wide
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

    condition:
        any of them
}