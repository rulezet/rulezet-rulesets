rule rule_Zoho_Assist_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Zoho Assist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Zoho Assist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Zoho_Assist_greyware_tool_keyword = /\s\-altgw\s.{0,1000}\.zohoassist\.com\s/ nocase ascii wide
                        $string2_Zoho_Assist_greyware_tool_keyword = /\s\-ms\sassist\.zoho\.com\s\-p\s443/ nocase ascii wide
                        $string3_Zoho_Assist_greyware_tool_keyword = /\s\-rr_flag\s.{0,1000}\s\-group\s.{0,1000}\s\-fileTransferGateways\s.{0,1000}\.zohoassist\.com\s\-ADMINAGENT/ nocase ascii wide
                        $string4_Zoho_Assist_greyware_tool_keyword = /\sSELECT\sProcessId\sFROM\sWin32_Process\s.{0,1000}\sName\=\'ZAAudioClient\.exe\'/ nocase ascii wide
                        $string5_Zoho_Assist_greyware_tool_keyword = /\sZA_Connect\.exe/ nocase ascii wide
                        $string6_Zoho_Assist_greyware_tool_keyword = /\sZAAudioClient\.exe/ nocase ascii wide
                        $string7_Zoho_Assist_greyware_tool_keyword = /\sZAFileTransfer\.exe/ nocase ascii wide
                        $string8_Zoho_Assist_greyware_tool_keyword = /\sZAService\.exe/ nocase ascii wide
                        $string9_Zoho_Assist_greyware_tool_keyword = /\.zohoassist\.com\.cn/ nocase ascii wide
                        $string10_Zoho_Assist_greyware_tool_keyword = /\.zohoassist\.jp/ nocase ascii wide
                        $string11_Zoho_Assist_greyware_tool_keyword = /\/ZA_Connect\.exe/ nocase ascii wide
                        $string12_Zoho_Assist_greyware_tool_keyword = /\/ZAAudioClient\.exe/ nocase ascii wide
                        $string13_Zoho_Assist_greyware_tool_keyword = /\/ZAFileTransfer\.exe/ nocase ascii wide
                        $string14_Zoho_Assist_greyware_tool_keyword = /\/ZAService\.exe/ nocase ascii wide
                        $string15_Zoho_Assist_greyware_tool_keyword = /\\AppData\\Local\\ZohoMeeting\\/ nocase ascii wide
                        $string16_Zoho_Assist_greyware_tool_keyword = /\\CurrentControlSet\\Services\\Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
                        $string17_Zoho_Assist_greyware_tool_keyword = /\\dctoolshardware\.exe/ nocase ascii wide
                        $string18_Zoho_Assist_greyware_tool_keyword = /\\InventoryApplicationFile\\zaservice\.exe/ nocase ascii wide
                        $string19_Zoho_Assist_greyware_tool_keyword = /\\log\\FileTransferWindowAppLog\.log/ nocase ascii wide
                        $string20_Zoho_Assist_greyware_tool_keyword = /\\Root\\InventoryApplicationFile\\za_connect\.exe/ nocase ascii wide
                        $string21_Zoho_Assist_greyware_tool_keyword = /\\RSTemp\\ZohoMeeting\\/ nocase ascii wide
                        $string22_Zoho_Assist_greyware_tool_keyword = /\\SafeBoot\\Network\\Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
                        $string23_Zoho_Assist_greyware_tool_keyword = /\\SOFTWARE\\Zoho\sAssist/ nocase ascii wide
                        $string24_Zoho_Assist_greyware_tool_keyword = /\\ZA_Connect\.exe/ nocase ascii wide
                        $string25_Zoho_Assist_greyware_tool_keyword = /\\ZA_Upgrader/ nocase ascii wide
                        $string26_Zoho_Assist_greyware_tool_keyword = /\\ZAAudioClient\.exe/ nocase ascii wide
                        $string27_Zoho_Assist_greyware_tool_keyword = /\\ZAFileTransfer\.exe/ nocase ascii wide
                        $string28_Zoho_Assist_greyware_tool_keyword = /\\ZAService\.exe/ nocase ascii wide
                        $string29_Zoho_Assist_greyware_tool_keyword = /\\ZAudioClientPipe_.{0,1000}ServerReadPipe/ nocase ascii wide
                        $string30_Zoho_Assist_greyware_tool_keyword = /\\ZAudioClientPipe_.{0,1000}ServerWritePipe/ nocase ascii wide
                        $string31_Zoho_Assist_greyware_tool_keyword = /\\ZMAgent\.exe/ nocase ascii wide
                        $string32_Zoho_Assist_greyware_tool_keyword = /\\Zoho\sAssist\\Zoho\sAssist\sRemote\ssupport/ nocase ascii wide
                        $string33_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\.7z/ nocase ascii wide
                        $string34_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\.exe/ nocase ascii wide
                        $string35_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\\agent\.exe/ nocase ascii wide
                        $string36_Zoho_Assist_greyware_tool_keyword = /\\zohomeeting\\agent\.exe/ nocase ascii wide
                        $string37_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\\agent_ui\.exe/ nocase ascii wide
                        $string38_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\\Connect\.exe/ nocase ascii wide
                        $string39_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\\Connection\.conf/ nocase ascii wide
                        $string40_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\\log\\.{0,1000}\.log/ nocase ascii wide
                        $string41_Zoho_Assist_greyware_tool_keyword = /\\ZohoMeeting\\ViewerUI\.exe/ nocase ascii wide
                        $string42_Zoho_Assist_greyware_tool_keyword = /\\ZohoTray\.exe/ nocase ascii wide
                        $string43_Zoho_Assist_greyware_tool_keyword = /\\ZohoURS\.exe/ nocase ascii wide
                        $string44_Zoho_Assist_greyware_tool_keyword = /\\ZohoURSService\.exe/ nocase ascii wide
                        $string45_Zoho_Assist_greyware_tool_keyword = /_Classes\\zohoassistlaunchv2/ nocase ascii wide
                        $string46_Zoho_Assist_greyware_tool_keyword = /assist\.zoho\.com/ nocase ascii wide
                        $string47_Zoho_Assist_greyware_tool_keyword = /downloads\.zohocdn\.com/ nocase ascii wide
                        $string48_Zoho_Assist_greyware_tool_keyword = /downloads\.zohodl\.com\.cn/ nocase ascii wide
                        $string49_Zoho_Assist_greyware_tool_keyword = /gateway\.zohoassist\.com/ nocase ascii wide
                        $string50_Zoho_Assist_greyware_tool_keyword = /https\:\/\/.{0,1000}\.zoho\.com\/pconnect/ nocase ascii wide
                        $string51_Zoho_Assist_greyware_tool_keyword = /https\:\/\/.{0,1000}\.zohoassist\.com\/w_socket/ nocase ascii wide
                        $string52_Zoho_Assist_greyware_tool_keyword = /https\:\/\/assist\.zoho\.com\/assist\-join\?key\=/ nocase ascii wide
                        $string53_Zoho_Assist_greyware_tool_keyword = /https\:\/\/assist\.zoho\.com\/customer\-session\-details\?client_token\=/ nocase ascii wide
                        $string54_Zoho_Assist_greyware_tool_keyword = /https\:\/\/assist\.zoho\.com\/join\?join_source\=EMAIL_INVITE/ nocase ascii wide
                        $string55_Zoho_Assist_greyware_tool_keyword = /https\:\/\/assist\.zoho\.com\/join\-session\?key\=/ nocase ascii wide
                        $string56_Zoho_Assist_greyware_tool_keyword = /https\:\/\/assist\.zoho\.com\/org\// nocase ascii wide
                        $string57_Zoho_Assist_greyware_tool_keyword = /https\:\/\/assist\.zoho\.com\/viewer\-assist/ nocase ascii wide
                        $string58_Zoho_Assist_greyware_tool_keyword = /https\:\/\/pubsub\.zoho\.com\/.{0,1000}_deskUserPresence\/pubsub/ nocase ascii wide
                        $string59_Zoho_Assist_greyware_tool_keyword = /https\:\/\/us4\-wms6\.zoho\.com/ nocase ascii wide
                        $string60_Zoho_Assist_greyware_tool_keyword = /ProductName\:Zoho\%\%20Assist.{0,1000}\sapptype\:ATTENDEE/ nocase ascii wide
                        $string61_Zoho_Assist_greyware_tool_keyword = /program\sfiles\s\(x86\)\\zohomeeting/ nocase ascii wide
                        $string62_Zoho_Assist_greyware_tool_keyword = "'ServiceName'>Zoho Assist-Remote Support" nocase ascii wide
                        $string63_Zoho_Assist_greyware_tool_keyword = /turn\-.{0,1000}\.zohomeeting\.com/ nocase ascii wide
                        $string64_Zoho_Assist_greyware_tool_keyword = /ZA_Connect\.exe\s/ nocase ascii wide
                        $string65_Zoho_Assist_greyware_tool_keyword = /ZA_Connect\.exe\.ApplicationCompany/ nocase ascii wide
                        $string66_Zoho_Assist_greyware_tool_keyword = /ZAFileTransfer\.exe\s/ nocase ascii wide
                        $string67_Zoho_Assist_greyware_tool_keyword = /ZAService\.exe\s/ nocase ascii wide
                        $string68_Zoho_Assist_greyware_tool_keyword = "ZOHO CORPORATION PRIVATE LIMITED" nocase ascii wide
                        $string69_Zoho_Assist_greyware_tool_keyword = /ZohoMeeting\.exe/ nocase ascii wide
                        $string70_Zoho_Assist_greyware_tool_keyword = /ZohoMeeting\\FileTransferSettings\.conf/ nocase ascii wide
                        $string71_Zoho_Assist_greyware_tool_keyword = /ZohoMeeting\\Service\.Conf/ nocase ascii wide

    condition:
        any of them
}