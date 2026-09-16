rule rule_LogMeIn_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LogMeIn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LogMeIn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_LogMeIn_greyware_tool_keyword = /\.console\.gotoassist\.com/ nocase ascii wide
                        $string2_LogMeIn_greyware_tool_keyword = /\.remoteview\.logmein\.com/ nocase ascii wide
                        $string3_LogMeIn_greyware_tool_keyword = /\/LMI_Rescue\.exe/ nocase ascii wide
                        $string4_LogMeIn_greyware_tool_keyword = /\/LMIRTechConsole\.exe/ nocase ascii wide
                        $string5_LogMeIn_greyware_tool_keyword = /\\AppData\\Local\\.{0,1000}\\rescue\.log/ nocase ascii wide
                        $string6_LogMeIn_greyware_tool_keyword = /\\AppData\\Local\\LMIR.{0,1000}\.tmp\.bat/ nocase ascii wide
                        $string7_LogMeIn_greyware_tool_keyword = /\\AppData\\Local\\LogMeIn\sRescue\sApplet\\/ nocase ascii wide
                        $string8_LogMeIn_greyware_tool_keyword = /\\AppData\\LocalLow\\LogMeIn\sRescue\\/ nocase ascii wide
                        $string9_LogMeIn_greyware_tool_keyword = /\\LMI_Rescue\.exe/ nocase ascii wide
                        $string10_LogMeIn_greyware_tool_keyword = /\\lmi_rescue_srv\.exe/ nocase ascii wide
                        $string11_LogMeIn_greyware_tool_keyword = /\\LMIGuardianEvt\.dll/ nocase ascii wide
                        $string12_LogMeIn_greyware_tool_keyword = /\\LMIR.{0,1000}\.tmp\\rarcc\.dll/ nocase ascii wide
                        $string13_LogMeIn_greyware_tool_keyword = /\\LMIRescue\-.{0,1000}\.clog/ nocase ascii wide
                        $string14_LogMeIn_greyware_tool_keyword = /\\LMIRescue\-.{0,1000}\.connlog/ nocase ascii wide
                        $string15_LogMeIn_greyware_tool_keyword = /\\LMIRescueCOL\.log/ nocase ascii wide
                        $string16_LogMeIn_greyware_tool_keyword = /\\LMIRescueMqttMessages_.{0,1000}\.dat/ nocase ascii wide
                        $string17_LogMeIn_greyware_tool_keyword = /\\LMIRescueUpdater\.log/ nocase ascii wide
                        $string18_LogMeIn_greyware_tool_keyword = /\\LMIRhook\.000\.dll/ nocase ascii wide
                        $string19_LogMeIn_greyware_tool_keyword = /\\lmirtechconsole\.exe/ nocase ascii wide
                        $string20_LogMeIn_greyware_tool_keyword = /\\LMIRTechConsole\.exe/ nocase ascii wide
                        $string21_LogMeIn_greyware_tool_keyword = /\\LMITrs\-.{0,1000}\.trs/ nocase ascii wide
                        $string22_LogMeIn_greyware_tool_keyword = /\\LogMeIn\sRescue\sApplet\\LMIR/ nocase ascii wide
                        $string23_LogMeIn_greyware_tool_keyword = /\\LogMeIn\sRescue\sApplet\\LMIR/ nocase ascii wide
                        $string24_LogMeIn_greyware_tool_keyword = /\\LogMeIn\sRescue\sAVI\sCodec\\/ nocase ascii wide
                        $string25_LogMeIn_greyware_tool_keyword = /\\logmein\srescue\stechnician\sconsole\\/ nocase ascii wide
                        $string26_LogMeIn_greyware_tool_keyword = /\\LogMeIn\\Dumps\\/ nocase ascii wide
                        $string27_LogMeIn_greyware_tool_keyword = /\\LogMeInRescue_ipc/ nocase ascii wide
                        $string28_LogMeIn_greyware_tool_keyword = /\\LogMeInRescue_rarc_r_/ nocase ascii wide
                        $string29_LogMeIn_greyware_tool_keyword = /\\LogMeInRescue_rarc_w_/ nocase ascii wide
                        $string30_LogMeIn_greyware_tool_keyword = /\\LogMeInRescueTechnicianConsole_x64/ nocase ascii wide
                        $string31_LogMeIn_greyware_tool_keyword = /\\ProgramData\\LogMeIn\\/ nocase ascii wide
                        $string32_LogMeIn_greyware_tool_keyword = /\\ractrlkeyhook\.dll/ nocase ascii wide
                        $string33_LogMeIn_greyware_tool_keyword = /\\RescueWinRTLib\.dll/ nocase ascii wide
                        $string34_LogMeIn_greyware_tool_keyword = /\\RescueWinRTLib\.dll/ nocase ascii wide
                        $string35_LogMeIn_greyware_tool_keyword = /\\Root\\InventoryApplicationFile\\support\-logmeinr/ nocase ascii wide
                        $string36_LogMeIn_greyware_tool_keyword = /\\RunOnce\\.{0,1000}LogMeInRescue_/ nocase ascii wide
                        $string37_LogMeIn_greyware_tool_keyword = /\\Software\\LogMeInRescue\\/ nocase ascii wide
                        $string38_LogMeIn_greyware_tool_keyword = /\\Start\sMenu\\Programs\\LogMeIn\sRescue\\/ nocase ascii wide
                        $string39_LogMeIn_greyware_tool_keyword = /\\Start\sMenu\\Programs\\LogMeIn/ nocase ascii wide
                        $string40_LogMeIn_greyware_tool_keyword = /\<Data\>LogMeIn\,\sInc\.\<\/Data\>/ nocase ascii wide
                        $string41_LogMeIn_greyware_tool_keyword = "9d2ce0345f4ee5798a49a8a13e33c7502a2ac655" nocase ascii wide
                        $string42_LogMeIn_greyware_tool_keyword = /control\..{0,1000}\.logmeinrescue\.com/ nocase ascii wide
                        $string43_LogMeIn_greyware_tool_keyword = /control\.rsc\-app.{0,1000}\.logmeinrescue\.com/ nocase ascii wide
                        $string44_LogMeIn_greyware_tool_keyword = /https\:\/\/secure\.logmeinrescue\.com\/R\?i\=2\&Code\=/ nocase ascii wide
                        $string45_LogMeIn_greyware_tool_keyword = /https\:\/\/secure\.logmeinrescue\.com\/TechnicianConsole\/Launch/ nocase ascii wide
                        $string46_LogMeIn_greyware_tool_keyword = /LMI_RescueRC\.exe/ nocase ascii wide
                        $string47_LogMeIn_greyware_tool_keyword = /LMIGuardianDll\.dll/ nocase ascii wide
                        $string48_LogMeIn_greyware_tool_keyword = /LMIGuardianSvc\.exe/ nocase ascii wide
                        $string49_LogMeIn_greyware_tool_keyword = /LogMeIn\sRescue\sTechnician\sConsole\.lnk/ nocase ascii wide
                        $string50_LogMeIn_greyware_tool_keyword = /LogMeInRescueTechnicianConsoleApp\.msi/ nocase ascii wide
                        $string51_LogMeIn_greyware_tool_keyword = /Support\-LogMeInRescue\.exe/ nocase ascii wide
                        $string52_LogMeIn_greyware_tool_keyword = /Support\-LogMeInRescue\.exe/ nocase ascii wide
                        $string53_LogMeIn_greyware_tool_keyword = /SUPPORT\-LOGMEINRESCUE\.EXE\-/ nocase ascii wide
                        $string54_LogMeIn_greyware_tool_keyword = /turn\.console\.gotoassist\.com/ nocase ascii wide

    condition:
        any of them
}