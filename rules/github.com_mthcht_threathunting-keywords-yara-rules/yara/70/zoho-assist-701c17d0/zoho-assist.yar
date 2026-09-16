rule Zoho_Assist
{
    meta:
        description = "Detection patterns for the tool 'Zoho Assist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Zoho Assist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-altgw\s.{0,100}\.zohoassist\.com\s/ nocase ascii wide
                        $string2 = /\s\-ms\sassist\.zoho\.com\s\-p\s443/ nocase ascii wide
                        $string3 = /\s\-rr_flag\s.{0,100}\s\-group\s.{0,100}\s\-fileTransferGateways\s.{0,100}\.zohoassist\.com\s\-ADMINAGENT/ nocase ascii wide
                        $string4 = /\sSELECT\sProcessId\sFROM\sWin32_Process\s.{0,100}\sName\=\'ZAAudioClient\.exe\'/ nocase ascii wide
                        $string5 = /\sZA_Connect\.exe/ nocase ascii wide
                        $string6 = /\sZAAudioClient\.exe/ nocase ascii wide
                        $string7 = /\sZAFileTransfer\.exe/ nocase ascii wide
                        $string8 = /\sZAService\.exe/ nocase ascii wide
                        $string9 = /\.zohoassist\.com\.cn/ nocase ascii wide
                        $string10 = /\.zohoassist\.jp/ nocase ascii wide
                        $string11 = /\/ZA_Connect\.exe/ nocase ascii wide
                        $string12 = /\/ZAAudioClient\.exe/ nocase ascii wide
                        $string13 = /\/ZAFileTransfer\.exe/ nocase ascii wide
                        $string14 = /\/ZAService\.exe/ nocase ascii wide
                        $string15 = /\\AppData\\Local\\ZohoMeeting\\/ nocase ascii wide
                        $string16 = /\\CurrentControlSet\\Services\\Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
                        $string17 = /\\dctoolshardware\.exe/ nocase ascii wide
                        $string18 = /\\InventoryApplicationFile\\zaservice\.exe/ nocase ascii wide
                        $string19 = /\\log\\FileTransferWindowAppLog\.log/ nocase ascii wide
                        $string20 = /\\Root\\InventoryApplicationFile\\za_connect\.exe/ nocase ascii wide
                        $string21 = /\\RSTemp\\ZohoMeeting\\/ nocase ascii wide
                        $string22 = /\\SafeBoot\\Network\\Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
                        $string23 = /\\SOFTWARE\\Zoho\sAssist/ nocase ascii wide
                        $string24 = /\\ZA_Connect\.exe/ nocase ascii wide
                        $string25 = /\\ZA_Upgrader/ nocase ascii wide
                        $string26 = /\\ZAAudioClient\.exe/ nocase ascii wide
                        $string27 = /\\ZAFileTransfer\.exe/ nocase ascii wide
                        $string28 = /\\ZAService\.exe/ nocase ascii wide
                        $string29 = /\\ZAudioClientPipe_.{0,100}ServerReadPipe/ nocase ascii wide
                        $string30 = /\\ZAudioClientPipe_.{0,100}ServerWritePipe/ nocase ascii wide
                        $string31 = /\\ZMAgent\.exe/ nocase ascii wide
                        $string32 = /\\Zoho\sAssist\\Zoho\sAssist\sRemote\ssupport/ nocase ascii wide
                        $string33 = /\\ZohoMeeting\.7z/ nocase ascii wide
                        $string34 = /\\ZohoMeeting\.exe/ nocase ascii wide
                        $string35 = /\\ZohoMeeting\\agent\.exe/ nocase ascii wide
                        $string36 = /\\zohomeeting\\agent\.exe/ nocase ascii wide
                        $string37 = /\\ZohoMeeting\\agent_ui\.exe/ nocase ascii wide
                        $string38 = /\\ZohoMeeting\\Connect\.exe/ nocase ascii wide
                        $string39 = /\\ZohoMeeting\\Connection\.conf/ nocase ascii wide
                        $string40 = /\\ZohoMeeting\\log\\.{0,100}\.log/ nocase ascii wide
                        $string41 = /\\ZohoMeeting\\ViewerUI\.exe/ nocase ascii wide
                        $string42 = /\\ZohoTray\.exe/ nocase ascii wide
                        $string43 = /\\ZohoURS\.exe/ nocase ascii wide
                        $string44 = /\\ZohoURSService\.exe/ nocase ascii wide
                        $string45 = /_Classes\\zohoassistlaunchv2/ nocase ascii wide
                        $string46 = /assist\.zoho\.com/ nocase ascii wide
                        $string47 = /downloads\.zohocdn\.com/ nocase ascii wide
                        $string48 = /downloads\.zohodl\.com\.cn/ nocase ascii wide
                        $string49 = /gateway\.zohoassist\.com/ nocase ascii wide
                        $string50 = /https\:\/\/.{0,100}\.zoho\.com\/pconnect/ nocase ascii wide
                        $string51 = /https\:\/\/.{0,100}\.zohoassist\.com\/w_socket/ nocase ascii wide
                        $string52 = /https\:\/\/assist\.zoho\.com\/assist\-join\?key\=/ nocase ascii wide
                        $string53 = /https\:\/\/assist\.zoho\.com\/customer\-session\-details\?client_token\=/ nocase ascii wide
                        $string54 = /https\:\/\/assist\.zoho\.com\/join\?join_source\=EMAIL_INVITE/ nocase ascii wide
                        $string55 = /https\:\/\/assist\.zoho\.com\/join\-session\?key\=/ nocase ascii wide
                        $string56 = /https\:\/\/assist\.zoho\.com\/org\// nocase ascii wide
                        $string57 = /https\:\/\/assist\.zoho\.com\/viewer\-assist/ nocase ascii wide
                        $string58 = /https\:\/\/pubsub\.zoho\.com\/.{0,100}_deskUserPresence\/pubsub/ nocase ascii wide
                        $string59 = /https\:\/\/us4\-wms6\.zoho\.com/ nocase ascii wide
                        $string60 = /ProductName\:Zoho\%\%20Assist.{0,100}\sapptype\:ATTENDEE/ nocase ascii wide
                        $string61 = /program\sfiles\s\(x86\)\\zohomeeting/ nocase ascii wide
                        $string62 = "'ServiceName'>Zoho Assist-Remote Support" nocase ascii wide
                        $string63 = /turn\-.{0,100}\.zohomeeting\.com/ nocase ascii wide
                        $string64 = /ZA_Connect\.exe\s/ nocase ascii wide
                        $string65 = /ZA_Connect\.exe\.ApplicationCompany/ nocase ascii wide
                        $string66 = /ZAFileTransfer\.exe\s/ nocase ascii wide
                        $string67 = /ZAService\.exe\s/ nocase ascii wide
                        $string68 = "ZOHO CORPORATION PRIVATE LIMITED" nocase ascii wide
                        $string69 = /ZohoMeeting\.exe/ nocase ascii wide
                        $string70 = /ZohoMeeting\\FileTransferSettings\.conf/ nocase ascii wide
                        $string71 = /ZohoMeeting\\Service\.Conf/ nocase ascii wide
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