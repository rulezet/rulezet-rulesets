rule tightvnc
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " -service TightVNC Server" nocase ascii wide
                        $string2 = /\.\\TightVNC1/ nocase ascii wide
                        $string3 = /\.\\TightVNC2/ nocase ascii wide
                        $string4 = /\.\\TightVNC3/ nocase ascii wide
                        $string5 = /\/tightvnc\-.{0,1000}\.msi/ nocase ascii wide
                        $string6 = /\\mlnhcpkomdeavomsjalt/ nocase ascii wide
                        $string7 = /\\Programs\\TightVNC/ nocase ascii wide
                        $string8 = /\\SOFTWARE\\WOW6432Node\\TightVNC\\/ nocase ascii wide
                        $string9 = /\\TightVNC\sServer/ nocase ascii wide
                        $string10 = /\\tightvnc\-/ nocase ascii wide
                        $string11 = /\\TightVNC_Service_Control/ nocase ascii wide
                        $string12 = /\\TVN_log_pipe_public_name/ nocase ascii wide
                        $string13 = ">TightVNC Viewer<" nocase ascii wide
                        $string14 = /00\:\\\.vnc\\/ nocase ascii wide
                        $string15 = /GlavSoft\sLLC\./ nocase ascii wide
                        $string16 = /HKCR\\\.vnc/ nocase ascii wide
                        $string17 = /program\sfiles\s\(x86\)\\tightvnc\\/ nocase ascii wide
                        $string18 = /ProgramData\\TightVNC/ nocase ascii wide
                        $string19 = "TightVNC Service" nocase ascii wide
                        $string20 = /TightVNC\sWeb\sSite\.url/ nocase ascii wide
                        $string21 = "tvnserver" nocase ascii wide
                        $string22 = /tvnserver\.exe/ nocase ascii wide
                        $string23 = /tvnviewer\.exe/ nocase ascii wide
                        $string24 = /VncViewer\.Config/ nocase ascii wide
                        $string25 = /www\.tightvnc\.com\/download\/.{0,1000}\=/ nocase ascii wide

    condition:
        any of them
}