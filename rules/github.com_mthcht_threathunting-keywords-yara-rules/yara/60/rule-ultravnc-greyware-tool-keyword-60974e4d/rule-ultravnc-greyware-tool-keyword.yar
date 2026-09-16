rule rule_UltraVNC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UltraVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UltraVNC"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_UltraVNC_greyware_tool_keyword = " start uvnc_service" nocase ascii wide
                        $string2_UltraVNC_greyware_tool_keyword = " stop uvnc_service" nocase ascii wide
                        $string3_UltraVNC_greyware_tool_keyword = /\sultravnc\.ini\s/ nocase ascii wide
                        $string4_UltraVNC_greyware_tool_keyword = /\svnc\.ini\s/ nocase ascii wide
                        $string5_UltraVNC_greyware_tool_keyword = "\"publisher\":\"uvnc bvba" nocase ascii wide
                        $string6_UltraVNC_greyware_tool_keyword = /\/downloads\/ultravnc\.html/ nocase ascii wide
                        $string7_UltraVNC_greyware_tool_keyword = /\\127\.0\.0\.1\-5900\.vnc/ nocase ascii wide
                        $string8_UltraVNC_greyware_tool_keyword = /\\AppData\\Roaming\\.{0,100}\-5900\.vnc/ nocase ascii wide
                        $string9_UltraVNC_greyware_tool_keyword = /\\AppData\\Roaming\\UltraVNC\\/ nocase ascii wide
                        $string10_UltraVNC_greyware_tool_keyword = /\\createpassword\.exe/ nocase ascii wide
                        $string11_UltraVNC_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\Ultravnc2_is1\\/ nocase ascii wide
                        $string12_UltraVNC_greyware_tool_keyword = /\\InventoryApplicationFile\\ultravnc_/ nocase ascii wide
                        $string13_UltraVNC_greyware_tool_keyword = /\\options\.vnc/ nocase ascii wide
                        $string14_UltraVNC_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\uvnc\sbvba\\/ nocase ascii wide
                        $string15_UltraVNC_greyware_tool_keyword = /\\Services\\EventLog\\Application\\UltraVNC\\/ nocase ascii wide
                        $string16_UltraVNC_greyware_tool_keyword = /\\SOFTWARE\\ORL\\VNCHooks\\Application_Prefs\\WinVNC/ nocase ascii wide
                        $string17_UltraVNC_greyware_tool_keyword = /\\ultravnc\.cer/ nocase ascii wide
                        $string18_UltraVNC_greyware_tool_keyword = /\\UltraVNC\.ini/ nocase ascii wide
                        $string19_UltraVNC_greyware_tool_keyword = /\\uvnc\sbvba\\UltraVNC\\/ nocase ascii wide
                        $string20_UltraVNC_greyware_tool_keyword = /\\uvnc_launch\.exe/ nocase ascii wide
                        $string21_UltraVNC_greyware_tool_keyword = /\\uvnc_settings\.ex/ nocase ascii wide
                        $string22_UltraVNC_greyware_tool_keyword = /\\uvnc_settings\.exe/ nocase ascii wide
                        $string23_UltraVNC_greyware_tool_keyword = /\\uvnckeyboardhelper\.exe/ nocase ascii wide
                        $string24_UltraVNC_greyware_tool_keyword = /\\vncviewer\.exe/ nocase ascii wide
                        $string25_UltraVNC_greyware_tool_keyword = /\\winvnc\.exe/ nocase ascii wide
                        $string26_UltraVNC_greyware_tool_keyword = /\\winvncsc\.exe/ nocase ascii wide
                        $string27_UltraVNC_greyware_tool_keyword = /\\winwvc\.exe/ nocase ascii wide
                        $string28_UltraVNC_greyware_tool_keyword = /bvba_UltraVNC_.{0,100}_exe/ nocase ascii wide
                        $string29_UltraVNC_greyware_tool_keyword = /certutil\.exe.{0,100}\s\-addstore\s\\"TrustedPublisher\\".{0,100}ultravnc\.cer/ nocase ascii wide
                        $string30_UltraVNC_greyware_tool_keyword = "'Company'>UltraVNC</Data>" nocase ascii wide
                        $string31_UltraVNC_greyware_tool_keyword = "'Description'>VNC server</Data>" nocase ascii wide
                        $string32_UltraVNC_greyware_tool_keyword = /firewall\sadd\sallowedprogram\s.{0,100}vncviewer\.exe.{0,100}\sENABLE\sALL/ nocase ascii wide
                        $string33_UltraVNC_greyware_tool_keyword = /firewall\sadd\sallowedprogram\s.{0,100}winvnc\.exe.{0,100}\sENABLE\sALL/ nocase ascii wide
                        $string34_UltraVNC_greyware_tool_keyword = "firewall add portopening TCP 5800 vnc5800" nocase ascii wide
                        $string35_UltraVNC_greyware_tool_keyword = "firewall add portopening TCP 5900 vnc5900" nocase ascii wide
                        $string36_UltraVNC_greyware_tool_keyword = /HKCR\\\.vnc/ nocase ascii wide
                        $string37_UltraVNC_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\uvnc\sbvba\\/ nocase ascii wide
                        $string38_UltraVNC_greyware_tool_keyword = /UltraVNC\sLauncher\.lnk/ nocase ascii wide
                        $string39_UltraVNC_greyware_tool_keyword = "ultravnc mslogonacl" nocase ascii wide
                        $string40_UltraVNC_greyware_tool_keyword = /UltraVNC\sRepeater\.lnk/ nocase ascii wide
                        $string41_UltraVNC_greyware_tool_keyword = /UltraVNC\sServer\sSettings\.lnk/ nocase ascii wide
                        $string42_UltraVNC_greyware_tool_keyword = /UltraVNC\sServer\.lnk/ nocase ascii wide
                        $string43_UltraVNC_greyware_tool_keyword = "ultravnc testauth" nocase ascii wide
                        $string44_UltraVNC_greyware_tool_keyword = /UltraVNC\sViewer\.lnk/ nocase ascii wide
                        $string45_UltraVNC_greyware_tool_keyword = /UltraVNC_.{0,100}_X86_Setup/ nocase ascii wide
                        $string46_UltraVNC_greyware_tool_keyword = /ULTRAVNC_1.{0,100}_X86_SETUP\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string47_UltraVNC_greyware_tool_keyword = "ultravnc_repeater" nocase ascii wide
                        $string48_UltraVNC_greyware_tool_keyword = "ultravnc_server" nocase ascii wide
                        $string49_UltraVNC_greyware_tool_keyword = "ultravnc_viewer" nocase ascii wide
                        $string50_UltraVNC_greyware_tool_keyword = "VNCviewer Config File" nocase ascii wide
                        $string51_UltraVNC_greyware_tool_keyword = /VncViewer\.Config/ nocase ascii wide
                        $string52_UltraVNC_greyware_tool_keyword = /VNCVIEWER\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string53_UltraVNC_greyware_tool_keyword = /WinVNC\.exe/ nocase ascii wide
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