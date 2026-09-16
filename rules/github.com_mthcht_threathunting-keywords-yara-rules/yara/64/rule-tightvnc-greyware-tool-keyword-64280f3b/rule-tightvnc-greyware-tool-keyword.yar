rule rule_tightvnc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tightvnc_greyware_tool_keyword = " -service TightVNC Server" nocase ascii wide
                        $string2_tightvnc_greyware_tool_keyword = /\.\\TightVNC1/ nocase ascii wide
                        $string3_tightvnc_greyware_tool_keyword = /\.\\TightVNC2/ nocase ascii wide
                        $string4_tightvnc_greyware_tool_keyword = /\.\\TightVNC3/ nocase ascii wide
                        $string5_tightvnc_greyware_tool_keyword = /\/tightvnc\-.{0,1000}\.msi/ nocase ascii wide
                        $string6_tightvnc_greyware_tool_keyword = /\\mlnhcpkomdeavomsjalt/ nocase ascii wide
                        $string7_tightvnc_greyware_tool_keyword = /\\Programs\\TightVNC/ nocase ascii wide
                        $string8_tightvnc_greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\TightVNC\\/ nocase ascii wide
                        $string9_tightvnc_greyware_tool_keyword = /\\TightVNC\sServer/ nocase ascii wide
                        $string10_tightvnc_greyware_tool_keyword = /\\tightvnc\-/ nocase ascii wide
                        $string11_tightvnc_greyware_tool_keyword = /\\TightVNC_Service_Control/ nocase ascii wide
                        $string12_tightvnc_greyware_tool_keyword = /\\TVN_log_pipe_public_name/ nocase ascii wide
                        $string13_tightvnc_greyware_tool_keyword = ">TightVNC Viewer<" nocase ascii wide
                        $string14_tightvnc_greyware_tool_keyword = /00\:\\\.vnc\\/ nocase ascii wide
                        $string15_tightvnc_greyware_tool_keyword = /GlavSoft\sLLC\./ nocase ascii wide
                        $string16_tightvnc_greyware_tool_keyword = /HKCR\\\.vnc/ nocase ascii wide
                        $string17_tightvnc_greyware_tool_keyword = /program\sfiles\s\(x86\)\\tightvnc\\/ nocase ascii wide
                        $string18_tightvnc_greyware_tool_keyword = /ProgramData\\TightVNC/ nocase ascii wide
                        $string19_tightvnc_greyware_tool_keyword = "TightVNC Service" nocase ascii wide
                        $string20_tightvnc_greyware_tool_keyword = /TightVNC\sWeb\sSite\.url/ nocase ascii wide
                        $string21_tightvnc_greyware_tool_keyword = "tvnserver" nocase ascii wide
                        $string22_tightvnc_greyware_tool_keyword = /tvnserver\.exe/ nocase ascii wide
                        $string23_tightvnc_greyware_tool_keyword = /tvnviewer\.exe/ nocase ascii wide
                        $string24_tightvnc_greyware_tool_keyword = /VncViewer\.Config/ nocase ascii wide
                        $string25_tightvnc_greyware_tool_keyword = /www\.tightvnc\.com\/download\/.{0,1000}\=/ nocase ascii wide

    condition:
        any of them
}