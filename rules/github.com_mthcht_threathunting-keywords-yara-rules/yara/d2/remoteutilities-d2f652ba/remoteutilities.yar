rule RemoteUtilities
{
    meta:
        description = "Detection patterns for the tool 'RemoteUtilities' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteUtilities"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sConnection\s\#.{0,100}\.\sConnection\sto\s\\".{0,100}\\"\sestablished\.\sMode\:\s\<Remote\scontrol\>\./ nocase ascii wide
                        $string2 = /\sConnection\s\#.{0,100}\.\sConnection\sto\s\\".{0,100}\\"\.\sSecurity\scheck\s\-\sOK\.\sMode\:\s\s\<Inventory\smanager\>/ nocase ascii wide
                        $string3 = /\sConnection\s\#.{0,100}\.\sConnection\sto\s\\".{0,100}\\"\.\sSecurity\scheck\s\-\sOK\.\sMode\:\s\<Command\s\(command\:\s.{0,100}\)\>/ nocase ascii wide
                        $string4 = /\sConnection\s\#.{0,100}\.\sDirect\sconnection\sto\s.{0,100}\s\(.{0,100}\:5650\)\./ nocase ascii wide
                        $string5 = /\s\-name\:.{0,100}\s\-password\:.{0,100}\s\-remoteexecute\s\-filename/ nocase ascii wide
                        $string6 = /\.remoteutilities\.com/ nocase ascii wide
                        $string7 = /\/host\-7\.2\.2\.0\.msi/ nocase ascii wide
                        $string8 = /\/rfusclient\.exe/ nocase ascii wide
                        $string9 = /\/rutserv\.exe/ nocase ascii wide
                        $string10 = /\/rutview\.exe/ nocase ascii wide
                        $string11 = "/usr/bin/r-agent"
                        $string12 = "/usr/bin/r-viewer"
                        $string13 = /\/usr\/share\/applications\/r\-agent\.desktop/
                        $string14 = /\/usr\/share\/applications\/r\-viewer\.desktop/
                        $string15 = /\/VPDAgent\.exe/ nocase ascii wide
                        $string16 = /\\.{0,100}\-.{0,100}\-.{0,100}_rut\-.{0,100}\.zip\.3bf/ nocase ascii wide
                        $string17 = /\\.{0,100}\-internet\-id\-log\.csv/ nocase ascii wide
                        $string18 = /\\AppData\\Local\\Downloaded\sInstallations\\.{0,100}\\server\-3\.3\.5\.0\.msi/ nocase ascii wide
                        $string19 = /\\AppData\\Local\\Downloaded\sInstallations\\.{0,100}\\viewer\-7\.2\.2\.0\.msi/ nocase ascii wide
                        $string20 = /\\AppData\\Local\\Temp\\.{0,100}\\server\-3\.3\.5\.0\.exe/ nocase ascii wide
                        $string21 = /\\AppData\\Local\\Temp\\.{0,100}\\server\-3\.3\.5\.0\.msi/ nocase ascii wide
                        $string22 = /\\AppData\\Local\\Temp\\rutserv/ nocase ascii wide
                        $string23 = /\\AppData\\Roaming\\Remote\sUtilities\sFiles/ nocase ascii wide
                        $string24 = /\\CurrentControlSet\\Services\\MiniInternetIdService/ nocase ascii wide
                        $string25 = /\\CurrentVersion\\Devices\\Remote\sUtilities\sPrinter/ nocase ascii wide
                        $string26 = /\\drivers\\x64\\rupdui\.dll/ nocase ascii wide
                        $string27 = /\\host\-7\.2\.2\.0\.msi/ nocase ascii wide
                        $string28 = /\\InternetIdService\.exe/ nocase ascii wide
                        $string29 = /\\InternetIdService_.{0,100}\-.{0,100}\-.{0,100}\.txt/ nocase ascii wide
                        $string30 = /\\Logs\\rut_log_.{0,100}\.html/ nocase ascii wide
                        $string31 = /\\Printers\\Remote\sUtilities\sPrinter\\/ nocase ascii wide
                        $string32 = /\\ProgramData\\Remote\sUtilities/ nocase ascii wide
                        $string33 = /\\remote\sutilities\s\-\shost\\/ nocase ascii wide
                        $string34 = /\\Remote\sUtilities\s\-\sHost\\/ nocase ascii wide
                        $string35 = /\\remote\sutilities\sagent\\/ nocase ascii wide
                        $string36 = /\\Remote\sUtilities\sAgent\\Logs/ nocase ascii wide
                        $string37 = /\\Remote\sUtilities\sFiles\\rdp_connections\\/ nocase ascii wide
                        $string38 = /\\Remote\sUtilities\sServer\\/ nocase ascii wide
                        $string39 = /\\Remote\sUtilities\\Logs/ nocase ascii wide
                        $string40 = /\\Remote\sUtilities\\MiniInternetId/ nocase ascii wide
                        $string41 = /\\rfusclient\.exe/ nocase ascii wide
                        $string42 = /\\rutserv\.exe/ nocase ascii wide
                        $string43 = /\\rutview\.exe/ nocase ascii wide
                        $string44 = /\\ru\-viewer\-portable\\/ nocase ascii wide
                        $string45 = /\\SOFTWARE\\Usoris\\Remote\sUtilities\\/ nocase ascii wide
                        $string46 = /\\spool\\drivers\\x64\\rupd\./ nocase ascii wide
                        $string47 = /\\System32\\rupdpm\.dll/ nocase ascii wide
                        $string48 = /\\Two\sPilots\\Agent\\Remote\sUtilities\sPrinter/ nocase ascii wide
                        $string49 = /\\unidrv_rupd\.dll/ nocase ascii wide
                        $string50 = /\\unidrv_rupd\.hlp/ nocase ascii wide
                        $string51 = /\\unidrvui_rupd\.dll/ nocase ascii wide
                        $string52 = /\\unires_vpd\.dll/ nocase ascii wide
                        $string53 = /\\viewer\-portable\-7\.2\.2\.0\\/ nocase ascii wide
                        $string54 = /\\VPDAgent\.exe/ nocase ascii wide
                        $string55 = "<a href=\"rutils:" nocase ascii wide
                        $string56 = "<Data>Product: Remote Utilities - Host -- " nocase ascii wide
                        $string57 = "<Data>Remote Utilities - Host</Data>" nocase ascii wide
                        $string58 = "<Data>Remote Utilities Server<" nocase ascii wide
                        $string59 = /\<Data\>Removed\sRemote\sUtilities\s\-\sHost\.\<\/Data\>/ nocase ascii wide
                        $string60 = /\>Installed\sRemote\sUtilities\s\-\sViewer\./ nocase ascii wide
                        $string61 = /\>Installed\sRemote\sUtilities\sServer\.\<\// nocase ascii wide
                        $string62 = ">Product: Remote Utilities - Viewer -- " nocase ascii wide
                        $string63 = ">Product: Remote Utilities Server -- " nocase ascii wide
                        $string64 = ">Remote Utilities - Viewer</" nocase ascii wide
                        $string65 = /InternetIdService\.exe/ nocase ascii wide
                        $string66 = /Program\sFiles\s\(x86\)\\Common\sFiles\\Two\sPilots/ nocase ascii wide
                        $string67 = /Remote\sUtilities\sPty\s\(Cy\)\sLtd\./ nocase ascii wide
                        $string68 = /RemoteAdmin\.RemoteUtilities/ nocase ascii wide
                        $string69 = /rfusclient\.exe\s/ nocase ascii wide
                        $string70 = /rutserv\.exe\s/ nocase ascii wide
                        $string71 = /rutserv\.exe\s\// nocase ascii wide
                        $string72 = /rutview\.exe\s/ nocase ascii wide
                        $string73 = /rutview\.exe\s\-/ nocase ascii wide
                        $string74 = /server\.remoteutilities\.com/ nocase ascii wide
                        $string75 = /Trojan\.RemoteUtilitiesRAT/ nocase ascii wide
                        $string76 = /Uninstall\sRemote\sUtilities\s\-\sViewer\.lnk/ nocase ascii wide
                        $string77 = /Uninstall\sRemote\sUtilities\sServer\.lnk/ nocase ascii wide
                        $string78 = /Uninstall\sRemote\sUtilities\.lnk/ nocase ascii wide
                        $string79 = /update\.remoteutilities\.net/ nocase ascii wide
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