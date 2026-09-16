rule Pulseway
{
    meta:
        description = "Detection patterns for the tool 'Pulseway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pulseway"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\<Data\>Received\sRequest\sRun\scommand\s.{0,1000}\<\/Data\>/ nocase ascii wide
                        $string2 = /\sPCMonitorManager\.exe/ nocase ascii wide
                        $string3 = /\sPCMonitorSrv\.exe/ nocase ascii wide
                        $string4 = /\spulseway_x64\.deb/ nocase ascii wide
                        $string5 = /\sPulseway_x64\.msi/ nocase ascii wide
                        $string6 = /\spulseway_x86\.deb/ nocase ascii wide
                        $string7 = /\/etc\/pulseway\/config\.xml/
                        $string8 = /\/PCMonitorManager\.exe/ nocase ascii wide
                        $string9 = /\/PCMonitorSrv\.exe/ nocase ascii wide
                        $string10 = /\/pcmrdp\-client\.dll/ nocase ascii wide
                        $string11 = /\/pulseway_x64\.deb/ nocase ascii wide
                        $string12 = /\/Pulseway_x64\.msi/ nocase ascii wide
                        $string13 = /\/pulseway_x86\.deb/ nocase ascii wide
                        $string14 = /\/systemd\/system\/pulseway\.service/ nocase ascii wide
                        $string15 = "/usr/sbin/pulseway"
                        $string16 = "/usr/sbin/pulsewayd"
                        $string17 = /\\AppData\\Roaming\\.{0,1000}\\RemoteDesktop\.exe/ nocase ascii wide
                        $string18 = /\\AppData\\Roaming\\.{0,1000}\\uac\.tmp/ nocase ascii wide
                        $string19 = /\\MMSOFT\sDesign\\PC\sMonitor/ nocase ascii wide
                        $string20 = /\\MMSOFT\sDesign\\Pulseway\\/ nocase ascii wide
                        $string21 = /\\PCMonitorManager\.exe/ nocase ascii wide
                        $string22 = /\\PCMonitorSrv\.exe/ nocase ascii wide
                        $string23 = /\\PCMonitorTypes\.dll/ nocase ascii wide
                        $string24 = /\\pcmrdp\-client\.dll/ nocase ascii wide
                        $string25 = /\\pcmupdate\.exe/ nocase ascii wide
                        $string26 = /\\pcmupdate\.exe\.config/ nocase ascii wide
                        $string27 = /\\Pulseway\sRemote\sControl\\/ nocase ascii wide
                        $string28 = /\\Pulseway\\/ nocase ascii wide
                        $string29 = /\\pulseway_x64\.deb/ nocase ascii wide
                        $string30 = /\\Pulseway_x64\.msi/ nocase ascii wide
                        $string31 = /\\pulseway_x86\.deb/ nocase ascii wide
                        $string32 = /\\PulsewayServiceCheck/ nocase ascii wide
                        $string33 = /\\pwyrc\-agent\.dll/ nocase ascii wide
                        $string34 = /\\pwy\-rd\\shell\\open\\command/ nocase ascii wide
                        $string35 = /\\RemoteDesktop_x64\.msi/ nocase ascii wide
                        $string36 = /\\SOFTWARE\\Microsoft\\Tracing\\PCMonitorSrv_RAS/ nocase ascii wide
                        $string37 = /\\Tasks\\PulsewayServiceCheck/ nocase ascii wide
                        $string38 = "<Data>Pulseway Remote Control</Data>" nocase ascii wide
                        $string39 = /\<Data\>Received\sRequest\sExecute\sautomation\s.{0,1000}\sscript\s.{0,1000}\sfrom\sdevice\sId/ nocase ascii wide
                        $string40 = /\<Data\>Received\sRequest\sGet\sRD\spool\sscore\s.{0,1000}pulseway\.com\/remote/ nocase ascii wide
                        $string41 = "<Provider Name=\"PC Monitor\" />" nocase ascii wide
                        $string42 = "<Provider Name=\"Pulseway\" />" nocase ascii wide
                        $string43 = /https\:\/\/.{0,1000}\.pulseway\.com\/app\/main\// nocase ascii wide
                        $string44 = "Pulseway -- Installation completed successfully" nocase ascii wide
                        $string45 = "Pulseway -- Removal completed successfully" nocase ascii wide
                        $string46 = "Pulseway Remote Control -- Installation completed successfully" nocase ascii wide
                        $string47 = /Pulseway\sRemote\sControl\.lnk/ nocase ascii wide
                        $string48 = /pulseway_x64\.pkg\.tar\.xz/ nocase ascii wide
                        $string49 = /pwyrc\-clip\.exe/ nocase ascii wide
                        $string50 = /rd\-asia\-au\-1\.pulseway\.com/ nocase ascii wide
                        $string51 = /rd\-eu\-de\-1\.pulseway\.com/ nocase ascii wide
                        $string52 = /rd\-eu\-ie\-1\.pulseway\.com/ nocase ascii wide
                        $string53 = /rd\-us\-east\-1\.pulseway\.com/ nocase ascii wide
                        $string54 = /rd\-us\-east\-2\.pulseway\.com/ nocase ascii wide
                        $string55 = /rd\-us\-west\-1\.pulseway\.com/ nocase ascii wide
                        $string56 = /Received\sRequest\sRun\sPowerShell\scommand\s\'.{0,1000}\'\sfrom\sdevice\sId/ nocase ascii wide
                        $string57 = /RemoteDesktop\.exe.{0,1000}pwy\-rd\:\?token\=/ nocase ascii wide
                        $string58 = "SC  QUERYEX \"PC Monitor\"" nocase ascii wide
                        $string59 = "service pulseway start" nocase ascii wide
                        $string60 = "service pulseway stop" nocase ascii wide
                        $string61 = "ServiceName\">Pulseway</Data>" nocase ascii wide
                        $string62 = "systemctl start pulseway" nocase ascii wide
                        $string63 = "systemctl status pulseway" nocase ascii wide
                        $string64 = "systemctl stop pulseway" nocase ascii wide
                        $string65 = /systemprofile\\AppData\\Roaming\\freerdp\\server/ nocase ascii wide
                        $string66 = /www\.pulseway\.com\/download\// nocase ascii wide

    condition:
        any of them
}