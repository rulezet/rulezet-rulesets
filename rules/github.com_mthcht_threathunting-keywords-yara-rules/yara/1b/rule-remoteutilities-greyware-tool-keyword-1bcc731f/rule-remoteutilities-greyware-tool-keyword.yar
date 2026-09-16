rule rule_RemoteUtilities_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RemoteUtilities' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteUtilities"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_RemoteUtilities_greyware_tool_keyword = /\sConnection\s\#.{0,1000}\.\sConnection\sto\s\\".{0,1000}\\"\sestablished\.\sMode\:\s\<Remote\scontrol\>\./ nocase ascii wide
                        $string2_RemoteUtilities_greyware_tool_keyword = /\sConnection\s\#.{0,1000}\.\sConnection\sto\s\\".{0,1000}\\"\.\sSecurity\scheck\s\-\sOK\.\sMode\:\s\s\<Inventory\smanager\>/ nocase ascii wide
                        $string3_RemoteUtilities_greyware_tool_keyword = /\sConnection\s\#.{0,1000}\.\sConnection\sto\s\\".{0,1000}\\"\.\sSecurity\scheck\s\-\sOK\.\sMode\:\s\<Command\s\(command\:\s.{0,1000}\)\>/ nocase ascii wide
                        $string4_RemoteUtilities_greyware_tool_keyword = /\sConnection\s\#.{0,1000}\.\sDirect\sconnection\sto\s.{0,1000}\s\(.{0,1000}\:5650\)\./ nocase ascii wide
                        $string5_RemoteUtilities_greyware_tool_keyword = /\s\-name\:.{0,1000}\s\-password\:.{0,1000}\s\-remoteexecute\s\-filename/ nocase ascii wide
                        $string6_RemoteUtilities_greyware_tool_keyword = /\.remoteutilities\.com/ nocase ascii wide
                        $string7_RemoteUtilities_greyware_tool_keyword = /\/host\-7\.2\.2\.0\.msi/ nocase ascii wide
                        $string8_RemoteUtilities_greyware_tool_keyword = /\/rfusclient\.exe/ nocase ascii wide
                        $string9_RemoteUtilities_greyware_tool_keyword = /\/rutserv\.exe/ nocase ascii wide
                        $string10_RemoteUtilities_greyware_tool_keyword = /\/rutview\.exe/ nocase ascii wide
                        $string11_RemoteUtilities_greyware_tool_keyword = "/usr/bin/r-agent"
                        $string12_RemoteUtilities_greyware_tool_keyword = "/usr/bin/r-viewer"
                        $string13_RemoteUtilities_greyware_tool_keyword = /\/usr\/share\/applications\/r\-agent\.desktop/
                        $string14_RemoteUtilities_greyware_tool_keyword = /\/usr\/share\/applications\/r\-viewer\.desktop/
                        $string15_RemoteUtilities_greyware_tool_keyword = /\/VPDAgent\.exe/ nocase ascii wide
                        $string16_RemoteUtilities_greyware_tool_keyword = /\\.{0,1000}\-.{0,1000}\-.{0,1000}_rut\-.{0,1000}\.zip\.3bf/ nocase ascii wide
                        $string17_RemoteUtilities_greyware_tool_keyword = /\\.{0,1000}\-internet\-id\-log\.csv/ nocase ascii wide
                        $string18_RemoteUtilities_greyware_tool_keyword = /\\AppData\\Local\\Downloaded\sInstallations\\.{0,1000}\\server\-3\.3\.5\.0\.msi/ nocase ascii wide
                        $string19_RemoteUtilities_greyware_tool_keyword = /\\AppData\\Local\\Downloaded\sInstallations\\.{0,1000}\\viewer\-7\.2\.2\.0\.msi/ nocase ascii wide
                        $string20_RemoteUtilities_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\server\-3\.3\.5\.0\.exe/ nocase ascii wide
                        $string21_RemoteUtilities_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\server\-3\.3\.5\.0\.msi/ nocase ascii wide
                        $string22_RemoteUtilities_greyware_tool_keyword = /\\AppData\\Local\\Temp\\rutserv/ nocase ascii wide
                        $string23_RemoteUtilities_greyware_tool_keyword = /\\AppData\\Roaming\\Remote\sUtilities\sFiles/ nocase ascii wide
                        $string24_RemoteUtilities_greyware_tool_keyword = /\\CurrentControlSet\\Services\\MiniInternetIdService/ nocase ascii wide
                        $string25_RemoteUtilities_greyware_tool_keyword = /\\CurrentVersion\\Devices\\Remote\sUtilities\sPrinter/ nocase ascii wide
                        $string26_RemoteUtilities_greyware_tool_keyword = /\\drivers\\x64\\rupdui\.dll/ nocase ascii wide
                        $string27_RemoteUtilities_greyware_tool_keyword = /\\host\-7\.2\.2\.0\.msi/ nocase ascii wide
                        $string28_RemoteUtilities_greyware_tool_keyword = /\\InternetIdService\.exe/ nocase ascii wide
                        $string29_RemoteUtilities_greyware_tool_keyword = /\\InternetIdService_.{0,1000}\-.{0,1000}\-.{0,1000}\.txt/ nocase ascii wide
                        $string30_RemoteUtilities_greyware_tool_keyword = /\\Logs\\rut_log_.{0,1000}\.html/ nocase ascii wide
                        $string31_RemoteUtilities_greyware_tool_keyword = /\\Printers\\Remote\sUtilities\sPrinter\\/ nocase ascii wide
                        $string32_RemoteUtilities_greyware_tool_keyword = /\\ProgramData\\Remote\sUtilities/ nocase ascii wide
                        $string33_RemoteUtilities_greyware_tool_keyword = /\\remote\sutilities\s\-\shost\\/ nocase ascii wide
                        $string34_RemoteUtilities_greyware_tool_keyword = /\\Remote\sUtilities\s\-\sHost\\/ nocase ascii wide
                        $string35_RemoteUtilities_greyware_tool_keyword = /\\remote\sutilities\sagent\\/ nocase ascii wide
                        $string36_RemoteUtilities_greyware_tool_keyword = /\\Remote\sUtilities\sAgent\\Logs/ nocase ascii wide
                        $string37_RemoteUtilities_greyware_tool_keyword = /\\Remote\sUtilities\sFiles\\rdp_connections\\/ nocase ascii wide
                        $string38_RemoteUtilities_greyware_tool_keyword = /\\Remote\sUtilities\sServer\\/ nocase ascii wide
                        $string39_RemoteUtilities_greyware_tool_keyword = /\\Remote\sUtilities\\Logs/ nocase ascii wide
                        $string40_RemoteUtilities_greyware_tool_keyword = /\\Remote\sUtilities\\MiniInternetId/ nocase ascii wide
                        $string41_RemoteUtilities_greyware_tool_keyword = /\\rfusclient\.exe/ nocase ascii wide
                        $string42_RemoteUtilities_greyware_tool_keyword = /\\rutserv\.exe/ nocase ascii wide
                        $string43_RemoteUtilities_greyware_tool_keyword = /\\rutview\.exe/ nocase ascii wide
                        $string44_RemoteUtilities_greyware_tool_keyword = /\\ru\-viewer\-portable\\/ nocase ascii wide
                        $string45_RemoteUtilities_greyware_tool_keyword = /\\SOFTWARE\\Usoris\\Remote\sUtilities\\/ nocase ascii wide
                        $string46_RemoteUtilities_greyware_tool_keyword = /\\spool\\drivers\\x64\\rupd\./ nocase ascii wide
                        $string47_RemoteUtilities_greyware_tool_keyword = /\\System32\\rupdpm\.dll/ nocase ascii wide
                        $string48_RemoteUtilities_greyware_tool_keyword = /\\Two\sPilots\\Agent\\Remote\sUtilities\sPrinter/ nocase ascii wide
                        $string49_RemoteUtilities_greyware_tool_keyword = /\\unidrv_rupd\.dll/ nocase ascii wide
                        $string50_RemoteUtilities_greyware_tool_keyword = /\\unidrv_rupd\.hlp/ nocase ascii wide
                        $string51_RemoteUtilities_greyware_tool_keyword = /\\unidrvui_rupd\.dll/ nocase ascii wide
                        $string52_RemoteUtilities_greyware_tool_keyword = /\\unires_vpd\.dll/ nocase ascii wide
                        $string53_RemoteUtilities_greyware_tool_keyword = /\\viewer\-portable\-7\.2\.2\.0\\/ nocase ascii wide
                        $string54_RemoteUtilities_greyware_tool_keyword = /\\VPDAgent\.exe/ nocase ascii wide
                        $string55_RemoteUtilities_greyware_tool_keyword = "<a href=\"rutils:" nocase ascii wide
                        $string56_RemoteUtilities_greyware_tool_keyword = "<Data>Product: Remote Utilities - Host -- " nocase ascii wide
                        $string57_RemoteUtilities_greyware_tool_keyword = "<Data>Remote Utilities - Host</Data>" nocase ascii wide
                        $string58_RemoteUtilities_greyware_tool_keyword = "<Data>Remote Utilities Server<" nocase ascii wide
                        $string59_RemoteUtilities_greyware_tool_keyword = /\<Data\>Removed\sRemote\sUtilities\s\-\sHost\.\<\/Data\>/ nocase ascii wide
                        $string60_RemoteUtilities_greyware_tool_keyword = /\>Installed\sRemote\sUtilities\s\-\sViewer\./ nocase ascii wide
                        $string61_RemoteUtilities_greyware_tool_keyword = /\>Installed\sRemote\sUtilities\sServer\.\<\// nocase ascii wide
                        $string62_RemoteUtilities_greyware_tool_keyword = ">Product: Remote Utilities - Viewer -- " nocase ascii wide
                        $string63_RemoteUtilities_greyware_tool_keyword = ">Product: Remote Utilities Server -- " nocase ascii wide
                        $string64_RemoteUtilities_greyware_tool_keyword = ">Remote Utilities - Viewer</" nocase ascii wide
                        $string65_RemoteUtilities_greyware_tool_keyword = /InternetIdService\.exe/ nocase ascii wide
                        $string66_RemoteUtilities_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Common\sFiles\\Two\sPilots/ nocase ascii wide
                        $string67_RemoteUtilities_greyware_tool_keyword = /Remote\sUtilities\sPty\s\(Cy\)\sLtd\./ nocase ascii wide
                        $string68_RemoteUtilities_greyware_tool_keyword = /RemoteAdmin\.RemoteUtilities/ nocase ascii wide
                        $string69_RemoteUtilities_greyware_tool_keyword = /rfusclient\.exe\s/ nocase ascii wide
                        $string70_RemoteUtilities_greyware_tool_keyword = /rutserv\.exe\s/ nocase ascii wide
                        $string71_RemoteUtilities_greyware_tool_keyword = /rutserv\.exe\s\// nocase ascii wide
                        $string72_RemoteUtilities_greyware_tool_keyword = /rutview\.exe\s/ nocase ascii wide
                        $string73_RemoteUtilities_greyware_tool_keyword = /rutview\.exe\s\-/ nocase ascii wide
                        $string74_RemoteUtilities_greyware_tool_keyword = /server\.remoteutilities\.com/ nocase ascii wide
                        $string75_RemoteUtilities_greyware_tool_keyword = /Trojan\.RemoteUtilitiesRAT/ nocase ascii wide
                        $string76_RemoteUtilities_greyware_tool_keyword = /Uninstall\sRemote\sUtilities\s\-\sViewer\.lnk/ nocase ascii wide
                        $string77_RemoteUtilities_greyware_tool_keyword = /Uninstall\sRemote\sUtilities\sServer\.lnk/ nocase ascii wide
                        $string78_RemoteUtilities_greyware_tool_keyword = /Uninstall\sRemote\sUtilities\.lnk/ nocase ascii wide
                        $string79_RemoteUtilities_greyware_tool_keyword = /update\.remoteutilities\.net/ nocase ascii wide

    condition:
        any of them
}