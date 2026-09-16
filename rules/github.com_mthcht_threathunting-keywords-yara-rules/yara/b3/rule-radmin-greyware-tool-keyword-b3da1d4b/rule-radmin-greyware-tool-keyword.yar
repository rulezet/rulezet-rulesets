rule rule_Radmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Radmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Radmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Radmin_greyware_tool_keyword = /\/Radmin\.exe/ nocase ascii wide
                        $string2_Radmin_greyware_tool_keyword = /\/Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
                        $string3_Radmin_greyware_tool_keyword = /\/Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
                        $string4_Radmin_greyware_tool_keyword = /\/Radmin_VPN_1\..{0,1000}\.exe/ nocase ascii wide
                        $string5_Radmin_greyware_tool_keyword = /\/rserver3\.exe/ nocase ascii wide
                        $string6_Radmin_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}_Radmin_3\..{0,1000}\.zip/ nocase ascii wide
                        $string7_Radmin_greyware_tool_keyword = /\\AppData\\Roaming\\Radmin/ nocase ascii wide
                        $string8_Radmin_greyware_tool_keyword = /\\Radmin\.exe/ nocase ascii wide
                        $string9_Radmin_greyware_tool_keyword = /\\RADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string10_Radmin_greyware_tool_keyword = /\\Radmin\\radmin\.rpb/ nocase ascii wide
                        $string11_Radmin_greyware_tool_keyword = /\\Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
                        $string12_Radmin_greyware_tool_keyword = /\\Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
                        $string13_Radmin_greyware_tool_keyword = /\\Radmin_VPN_1\..{0,1000}\.exe/ nocase ascii wide
                        $string14_Radmin_greyware_tool_keyword = /\\rserver3\.exe/ nocase ascii wide
                        $string15_Radmin_greyware_tool_keyword = /\\rsetup64\.exe.{0,1000}\/stop/ nocase ascii wide
                        $string16_Radmin_greyware_tool_keyword = /\\rsl\.exe\s\/setup/ nocase ascii wide
                        $string17_Radmin_greyware_tool_keyword = /\\rsl\.exe.{0,1000}\/stop/ nocase ascii wide
                        $string18_Radmin_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Radmin\sServer\s/ nocase ascii wide
                        $string19_Radmin_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Radmin\sViewer\s/ nocase ascii wide
                        $string20_Radmin_greyware_tool_keyword = /\\SysWOW64\\rserver30\\FamItrf2/ nocase ascii wide
                        $string21_Radmin_greyware_tool_keyword = /\\SysWOW64\\rserver30\\FamItrfc/ nocase ascii wide
                        $string22_Radmin_greyware_tool_keyword = /\\Windows\\SysWOW64\\rserver30\\/ nocase ascii wide
                        $string23_Radmin_greyware_tool_keyword = /\>Famatech\sCorp\.\</ nocase ascii wide
                        $string24_Radmin_greyware_tool_keyword = /download\.radmin\.com/ nocase ascii wide
                        $string25_Radmin_greyware_tool_keyword = /download\.radmin\-vpn\.com/ nocase ascii wide
                        $string26_Radmin_greyware_tool_keyword = /HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\/ nocase ascii wide
                        $string27_Radmin_greyware_tool_keyword = "netsh advfirewall firewall add rule name=\"Radmin Server " nocase ascii wide
                        $string28_Radmin_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Radmin\sViewer\s3\\/ nocase ascii wide
                        $string29_Radmin_greyware_tool_keyword = "radmin /connect:" nocase ascii wide
                        $string30_Radmin_greyware_tool_keyword = "Radmin Server V3" nocase ascii wide
                        $string31_Radmin_greyware_tool_keyword = /Radmin\sViewer\s3\\CHATLOGS\\/ nocase ascii wide
                        $string32_Radmin_greyware_tool_keyword = /Radmin\sViewer\s3\\rchatx\.dll/ nocase ascii wide
                        $string33_Radmin_greyware_tool_keyword = /radmin\.exe.{0,1000}\s\/connect\:/ nocase ascii wide
                        $string34_Radmin_greyware_tool_keyword = "rserver3 /start" nocase ascii wide
                        $string35_Radmin_greyware_tool_keyword = "rserver3 /stop" nocase ascii wide
                        $string36_Radmin_greyware_tool_keyword = /rserver3\.exe.{0,1000}\/start/ nocase ascii wide
                        $string37_Radmin_greyware_tool_keyword = /rserver3\.exe.{0,1000}\/stop/ nocase ascii wide
                        $string38_Radmin_greyware_tool_keyword = /Settings\sfor\sRadmin\sServer\.lnk/ nocase ascii wide
                        $string39_Radmin_greyware_tool_keyword = /Stop\sRadmin\sServer\.lnk/ nocase ascii wide
                        $string40_Radmin_greyware_tool_keyword = /support\.radmin\.com/ nocase ascii wide

    condition:
        any of them
}