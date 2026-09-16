rule rule_ComodoRMM__Itarian_RMM__greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ComodoRMM (Itarian RMM)' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ComodoRMM (Itarian RMM)"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\.comodo\.com\/static\/frontend\/static\-pages\/enroll\-wizard\/token/ nocase ascii wide
                        $string2_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\/RemoteControlSetup\.exe/ nocase ascii wide
                        $string3_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\/tmp\/.{0,1000}\/enroll\.sh/
                        $string4_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\/tmp\/.{0,1000}\/itsm\.service/
                        $string5_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\/tmp\/.{0,1000}\/itsm\-linux/
                        $string6_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\AppData\\Local\\Temp\\ITarian_Remote_Access_/ nocase ascii wide
                        $string7_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\AppData\\Local\\Temp\\Remote_Control_by_Itarian/ nocase ascii wide
                        $string8_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\ComodoRemoteControl\.exe/ nocase ascii wide
                        $string9_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\CurrentControlSet\\Services\\ItsmRsp/ nocase ascii wide
                        $string10_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\CurrentControlSet\\Services\\ITSMService/ nocase ascii wide
                        $string11_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\CurrentControlSet\\Services\\RmmService/ nocase ascii wide
                        $string12_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\ITarian\sRemote\sAccess\.lnk/ nocase ascii wide
                        $string13_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\itarian\\endpoint\smanager\\itsmagent\.exe/ nocase ascii wide
                        $string14_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\itarian\\endpoint\smanager\\itsmservice\.exe/ nocase ascii wide
                        $string15_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\itarian\\endpoint\smanager\\rhost\.exe/ nocase ascii wide
                        $string16_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\ITarian\\RemoteControl/ nocase ascii wide
                        $string17_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\ITarian_Remote_Access_.{0,1000}\.log/ nocase ascii wide
                        $string18_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\ITarianRemoteAccess\.exe/ nocase ascii wide
                        $string19_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\ITarian\\Endpoint\sManager\\/ nocase ascii wide
                        $string20_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\ITarian\\RemoteControl\\/ nocase ascii wide
                        $string21_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\Remote_Control_by_ITarian_.{0,1000}\.log/ nocase ascii wide
                        $string22_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\remotecontrol\\rcontrol\.exe/ nocase ascii wide
                        $string23_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\remotecontrol\\rviewer\.exe/ nocase ascii wide
                        $string24_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\RemoteControlbyITarian\s\(3\)\.exe/ nocase ascii wide
                        $string25_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\RemoteControlbyITarian_\(3\)\.exe/ nocase ascii wide
                        $string26_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\RemoteControlSetup\.exe/ nocase ascii wide
                        $string27_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\RmmService\.exe/ nocase ascii wide
                        $string28_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\SOFTWARE\\ITarian\\RemoteControl/ nocase ascii wide
                        $string29_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\ITarian\\ITSM\\/ nocase ascii wide
                        $string30_ComodoRMM__Itarian_RMM__greyware_tool_keyword = ">Remote Control by Itarian<" nocase ascii wide
                        $string31_ComodoRMM__Itarian_RMM__greyware_tool_keyword = ">RmmService<" nocase ascii wide
                        $string32_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /cwn\-log\-collector\-production\-clone\..{0,1000}\.elasticbeanstalk\.com/ nocase ascii wide
                        $string33_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /ITarianRemoteAccessSetup\.exe/ nocase ascii wide
                        $string34_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /Linux\sITSM\sAgent\/.{0,1000}\s\-e\s\/tmp\/install\.sh\s/
                        $string35_ComodoRMM__Itarian_RMM__greyware_tool_keyword = /mdmsupport\.comodo\.com/ nocase ascii wide

    condition:
        any of them
}