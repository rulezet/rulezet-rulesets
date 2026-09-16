rule ComodoRMM__Itarian_RMM_
{
    meta:
        description = "Detection patterns for the tool 'ComodoRMM (Itarian RMM)' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ComodoRMM (Itarian RMM)"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.comodo\.com\/static\/frontend\/static\-pages\/enroll\-wizard\/token/ nocase ascii wide
                        $string2 = /\/RemoteControlSetup\.exe/ nocase ascii wide
                        $string3 = /\/tmp\/.{0,1000}\/enroll\.sh/
                        $string4 = /\/tmp\/.{0,1000}\/itsm\.service/
                        $string5 = /\/tmp\/.{0,1000}\/itsm\-linux/
                        $string6 = /\\AppData\\Local\\Temp\\ITarian_Remote_Access_/ nocase ascii wide
                        $string7 = /\\AppData\\Local\\Temp\\Remote_Control_by_Itarian/ nocase ascii wide
                        $string8 = /\\ComodoRemoteControl\.exe/ nocase ascii wide
                        $string9 = /\\CurrentControlSet\\Services\\ItsmRsp/ nocase ascii wide
                        $string10 = /\\CurrentControlSet\\Services\\ITSMService/ nocase ascii wide
                        $string11 = /\\CurrentControlSet\\Services\\RmmService/ nocase ascii wide
                        $string12 = /\\ITarian\sRemote\sAccess\.lnk/ nocase ascii wide
                        $string13 = /\\itarian\\endpoint\smanager\\itsmagent\.exe/ nocase ascii wide
                        $string14 = /\\itarian\\endpoint\smanager\\itsmservice\.exe/ nocase ascii wide
                        $string15 = /\\itarian\\endpoint\smanager\\rhost\.exe/ nocase ascii wide
                        $string16 = /\\ITarian\\RemoteControl/ nocase ascii wide
                        $string17 = /\\ITarian_Remote_Access_.{0,1000}\.log/ nocase ascii wide
                        $string18 = /\\ITarianRemoteAccess\.exe/ nocase ascii wide
                        $string19 = /\\Program\sFiles\s\(x86\)\\ITarian\\Endpoint\sManager\\/ nocase ascii wide
                        $string20 = /\\Program\sFiles\s\(x86\)\\ITarian\\RemoteControl\\/ nocase ascii wide
                        $string21 = /\\Remote_Control_by_ITarian_.{0,1000}\.log/ nocase ascii wide
                        $string22 = /\\remotecontrol\\rcontrol\.exe/ nocase ascii wide
                        $string23 = /\\remotecontrol\\rviewer\.exe/ nocase ascii wide
                        $string24 = /\\RemoteControlbyITarian\s\(3\)\.exe/ nocase ascii wide
                        $string25 = /\\RemoteControlbyITarian_\(3\)\.exe/ nocase ascii wide
                        $string26 = /\\RemoteControlSetup\.exe/ nocase ascii wide
                        $string27 = /\\RmmService\.exe/ nocase ascii wide
                        $string28 = /\\SOFTWARE\\ITarian\\RemoteControl/ nocase ascii wide
                        $string29 = /\\SOFTWARE\\WOW6432Node\\ITarian\\ITSM\\/ nocase ascii wide
                        $string30 = ">Remote Control by Itarian<" nocase ascii wide
                        $string31 = ">RmmService<" nocase ascii wide
                        $string32 = /cwn\-log\-collector\-production\-clone\..{0,1000}\.elasticbeanstalk\.com/ nocase ascii wide
                        $string33 = /ITarianRemoteAccessSetup\.exe/ nocase ascii wide
                        $string34 = /Linux\sITSM\sAgent\/.{0,1000}\s\-e\s\/tmp\/install\.sh\s/
                        $string35 = /mdmsupport\.comodo\.com/ nocase ascii wide

    condition:
        any of them
}