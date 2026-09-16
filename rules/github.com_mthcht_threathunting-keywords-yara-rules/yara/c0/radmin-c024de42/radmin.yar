rule Radmin
{
    meta:
        description = "Detection patterns for the tool 'Radmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Radmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/Radmin\.exe/ nocase ascii wide
                        $string2 = /\/Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
                        $string3 = /\/Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
                        $string4 = /\/Radmin_VPN_1\..{0,1000}\.exe/ nocase ascii wide
                        $string5 = /\/rserver3\.exe/ nocase ascii wide
                        $string6 = /\\AppData\\Local\\Temp\\.{0,1000}_Radmin_3\..{0,1000}\.zip/ nocase ascii wide
                        $string7 = /\\AppData\\Roaming\\Radmin/ nocase ascii wide
                        $string8 = /\\Radmin\.exe/ nocase ascii wide
                        $string9 = /\\RADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string10 = /\\Radmin\\radmin\.rpb/ nocase ascii wide
                        $string11 = /\\Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
                        $string12 = /\\Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
                        $string13 = /\\Radmin_VPN_1\..{0,1000}\.exe/ nocase ascii wide
                        $string14 = /\\rserver3\.exe/ nocase ascii wide
                        $string15 = /\\rsetup64\.exe.{0,1000}\/stop/ nocase ascii wide
                        $string16 = /\\rsl\.exe\s\/setup/ nocase ascii wide
                        $string17 = /\\rsl\.exe.{0,1000}\/stop/ nocase ascii wide
                        $string18 = /\\Start\sMenu\\Programs\\Radmin\sServer\s/ nocase ascii wide
                        $string19 = /\\Start\sMenu\\Programs\\Radmin\sViewer\s/ nocase ascii wide
                        $string20 = /\\SysWOW64\\rserver30\\FamItrf2/ nocase ascii wide
                        $string21 = /\\SysWOW64\\rserver30\\FamItrfc/ nocase ascii wide
                        $string22 = /\\Windows\\SysWOW64\\rserver30\\/ nocase ascii wide
                        $string23 = /\>Famatech\sCorp\.\</ nocase ascii wide
                        $string24 = /download\.radmin\.com/ nocase ascii wide
                        $string25 = /download\.radmin\-vpn\.com/ nocase ascii wide
                        $string26 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\/ nocase ascii wide
                        $string27 = "netsh advfirewall firewall add rule name=\"Radmin Server " nocase ascii wide
                        $string28 = /Program\sFiles\s\(x86\)\\Radmin\sViewer\s3\\/ nocase ascii wide
                        $string29 = "radmin /connect:" nocase ascii wide
                        $string30 = "Radmin Server V3" nocase ascii wide
                        $string31 = /Radmin\sViewer\s3\\CHATLOGS\\/ nocase ascii wide
                        $string32 = /Radmin\sViewer\s3\\rchatx\.dll/ nocase ascii wide
                        $string33 = /radmin\.exe.{0,1000}\s\/connect\:/ nocase ascii wide
                        $string34 = "rserver3 /start" nocase ascii wide
                        $string35 = "rserver3 /stop" nocase ascii wide
                        $string36 = /rserver3\.exe.{0,1000}\/start/ nocase ascii wide
                        $string37 = /rserver3\.exe.{0,1000}\/stop/ nocase ascii wide
                        $string38 = /Settings\sfor\sRadmin\sServer\.lnk/ nocase ascii wide
                        $string39 = /Stop\sRadmin\sServer\.lnk/ nocase ascii wide
                        $string40 = /support\.radmin\.com/ nocase ascii wide

    condition:
        any of them
}