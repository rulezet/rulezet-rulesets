rule rule_Pulseway_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pulseway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pulseway"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Pulseway_greyware_tool_keyword = /\s\<Data\>Received\sRequest\sRun\scommand\s.{0,100}\<\/Data\>/ nocase ascii wide
                        $string2_Pulseway_greyware_tool_keyword = /\sPCMonitorManager\.exe/ nocase ascii wide
                        $string3_Pulseway_greyware_tool_keyword = /\sPCMonitorSrv\.exe/ nocase ascii wide
                        $string4_Pulseway_greyware_tool_keyword = /\spulseway_x64\.deb/ nocase ascii wide
                        $string5_Pulseway_greyware_tool_keyword = /\sPulseway_x64\.msi/ nocase ascii wide
                        $string6_Pulseway_greyware_tool_keyword = /\spulseway_x86\.deb/ nocase ascii wide
                        $string7_Pulseway_greyware_tool_keyword = /\/etc\/pulseway\/config\.xml/
                        $string8_Pulseway_greyware_tool_keyword = /\/PCMonitorManager\.exe/ nocase ascii wide
                        $string9_Pulseway_greyware_tool_keyword = /\/PCMonitorSrv\.exe/ nocase ascii wide
                        $string10_Pulseway_greyware_tool_keyword = /\/pcmrdp\-client\.dll/ nocase ascii wide
                        $string11_Pulseway_greyware_tool_keyword = /\/pulseway_x64\.deb/ nocase ascii wide
                        $string12_Pulseway_greyware_tool_keyword = /\/Pulseway_x64\.msi/ nocase ascii wide
                        $string13_Pulseway_greyware_tool_keyword = /\/pulseway_x86\.deb/ nocase ascii wide
                        $string14_Pulseway_greyware_tool_keyword = /\/systemd\/system\/pulseway\.service/ nocase ascii wide
                        $string15_Pulseway_greyware_tool_keyword = "/usr/sbin/pulseway"
                        $string16_Pulseway_greyware_tool_keyword = "/usr/sbin/pulsewayd"
                        $string17_Pulseway_greyware_tool_keyword = /\\AppData\\Roaming\\.{0,100}\\RemoteDesktop\.exe/ nocase ascii wide
                        $string18_Pulseway_greyware_tool_keyword = /\\AppData\\Roaming\\.{0,100}\\uac\.tmp/ nocase ascii wide
                        $string19_Pulseway_greyware_tool_keyword = /\\MMSOFT\sDesign\\PC\sMonitor/ nocase ascii wide
                        $string20_Pulseway_greyware_tool_keyword = /\\MMSOFT\sDesign\\Pulseway\\/ nocase ascii wide
                        $string21_Pulseway_greyware_tool_keyword = /\\PCMonitorManager\.exe/ nocase ascii wide
                        $string22_Pulseway_greyware_tool_keyword = /\\PCMonitorSrv\.exe/ nocase ascii wide
                        $string23_Pulseway_greyware_tool_keyword = /\\PCMonitorTypes\.dll/ nocase ascii wide
                        $string24_Pulseway_greyware_tool_keyword = /\\pcmrdp\-client\.dll/ nocase ascii wide
                        $string25_Pulseway_greyware_tool_keyword = /\\pcmupdate\.exe/ nocase ascii wide
                        $string26_Pulseway_greyware_tool_keyword = /\\pcmupdate\.exe\.config/ nocase ascii wide
                        $string27_Pulseway_greyware_tool_keyword = /\\Pulseway\sRemote\sControl\\/ nocase ascii wide
                        $string28_Pulseway_greyware_tool_keyword = /\\Pulseway\\/ nocase ascii wide
                        $string29_Pulseway_greyware_tool_keyword = /\\pulseway_x64\.deb/ nocase ascii wide
                        $string30_Pulseway_greyware_tool_keyword = /\\Pulseway_x64\.msi/ nocase ascii wide
                        $string31_Pulseway_greyware_tool_keyword = /\\pulseway_x86\.deb/ nocase ascii wide
                        $string32_Pulseway_greyware_tool_keyword = /\\PulsewayServiceCheck/ nocase ascii wide
                        $string33_Pulseway_greyware_tool_keyword = /\\pwyrc\-agent\.dll/ nocase ascii wide
                        $string34_Pulseway_greyware_tool_keyword = /\\pwy\-rd\\shell\\open\\command/ nocase ascii wide
                        $string35_Pulseway_greyware_tool_keyword = /\\RemoteDesktop_x64\.msi/ nocase ascii wide
                        $string36_Pulseway_greyware_tool_keyword = /\\SOFTWARE\\Microsoft\\Tracing\\PCMonitorSrv_RAS/ nocase ascii wide
                        $string37_Pulseway_greyware_tool_keyword = /\\Tasks\\PulsewayServiceCheck/ nocase ascii wide
                        $string38_Pulseway_greyware_tool_keyword = "<Data>Pulseway Remote Control</Data>" nocase ascii wide
                        $string39_Pulseway_greyware_tool_keyword = /\<Data\>Received\sRequest\sExecute\sautomation\s.{0,100}\sscript\s.{0,100}\sfrom\sdevice\sId/ nocase ascii wide
                        $string40_Pulseway_greyware_tool_keyword = /\<Data\>Received\sRequest\sGet\sRD\spool\sscore\s.{0,100}pulseway\.com\/remote/ nocase ascii wide
                        $string41_Pulseway_greyware_tool_keyword = "<Provider Name=\"PC Monitor\" />" nocase ascii wide
                        $string42_Pulseway_greyware_tool_keyword = "<Provider Name=\"Pulseway\" />" nocase ascii wide
                        $string43_Pulseway_greyware_tool_keyword = /https\:\/\/.{0,100}\.pulseway\.com\/app\/main\// nocase ascii wide
                        $string44_Pulseway_greyware_tool_keyword = "Pulseway -- Installation completed successfully" nocase ascii wide
                        $string45_Pulseway_greyware_tool_keyword = "Pulseway -- Removal completed successfully" nocase ascii wide
                        $string46_Pulseway_greyware_tool_keyword = "Pulseway Remote Control -- Installation completed successfully" nocase ascii wide
                        $string47_Pulseway_greyware_tool_keyword = /Pulseway\sRemote\sControl\.lnk/ nocase ascii wide
                        $string48_Pulseway_greyware_tool_keyword = /pulseway_x64\.pkg\.tar\.xz/ nocase ascii wide
                        $string49_Pulseway_greyware_tool_keyword = /pwyrc\-clip\.exe/ nocase ascii wide
                        $string50_Pulseway_greyware_tool_keyword = /rd\-asia\-au\-1\.pulseway\.com/ nocase ascii wide
                        $string51_Pulseway_greyware_tool_keyword = /rd\-eu\-de\-1\.pulseway\.com/ nocase ascii wide
                        $string52_Pulseway_greyware_tool_keyword = /rd\-eu\-ie\-1\.pulseway\.com/ nocase ascii wide
                        $string53_Pulseway_greyware_tool_keyword = /rd\-us\-east\-1\.pulseway\.com/ nocase ascii wide
                        $string54_Pulseway_greyware_tool_keyword = /rd\-us\-east\-2\.pulseway\.com/ nocase ascii wide
                        $string55_Pulseway_greyware_tool_keyword = /rd\-us\-west\-1\.pulseway\.com/ nocase ascii wide
                        $string56_Pulseway_greyware_tool_keyword = /Received\sRequest\sRun\sPowerShell\scommand\s\'.{0,100}\'\sfrom\sdevice\sId/ nocase ascii wide
                        $string57_Pulseway_greyware_tool_keyword = /RemoteDesktop\.exe.{0,100}pwy\-rd\:\?token\=/ nocase ascii wide
                        $string58_Pulseway_greyware_tool_keyword = "SC  QUERYEX \"PC Monitor\"" nocase ascii wide
                        $string59_Pulseway_greyware_tool_keyword = "service pulseway start" nocase ascii wide
                        $string60_Pulseway_greyware_tool_keyword = "service pulseway stop" nocase ascii wide
                        $string61_Pulseway_greyware_tool_keyword = "ServiceName\">Pulseway</Data>" nocase ascii wide
                        $string62_Pulseway_greyware_tool_keyword = "systemctl start pulseway" nocase ascii wide
                        $string63_Pulseway_greyware_tool_keyword = "systemctl status pulseway" nocase ascii wide
                        $string64_Pulseway_greyware_tool_keyword = "systemctl stop pulseway" nocase ascii wide
                        $string65_Pulseway_greyware_tool_keyword = /systemprofile\\AppData\\Roaming\\freerdp\\server/ nocase ascii wide
                        $string66_Pulseway_greyware_tool_keyword = /www\.pulseway\.com\/download\// nocase ascii wide
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