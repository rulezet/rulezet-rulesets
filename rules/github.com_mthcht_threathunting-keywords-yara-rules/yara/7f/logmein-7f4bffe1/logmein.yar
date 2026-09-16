rule LogMeIn
{
    meta:
        description = "Detection patterns for the tool 'LogMeIn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LogMeIn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.console\.gotoassist\.com/ nocase ascii wide
                        $string2 = /\.remoteview\.logmein\.com/ nocase ascii wide
                        $string3 = /\/LMI_Rescue\.exe/ nocase ascii wide
                        $string4 = /\/LMIRTechConsole\.exe/ nocase ascii wide
                        $string5 = /\\AppData\\Local\\.{0,100}\\rescue\.log/ nocase ascii wide
                        $string6 = /\\AppData\\Local\\LMIR.{0,100}\.tmp\.bat/ nocase ascii wide
                        $string7 = /\\AppData\\Local\\LogMeIn\sRescue\sApplet\\/ nocase ascii wide
                        $string8 = /\\AppData\\LocalLow\\LogMeIn\sRescue\\/ nocase ascii wide
                        $string9 = /\\LMI_Rescue\.exe/ nocase ascii wide
                        $string10 = /\\lmi_rescue_srv\.exe/ nocase ascii wide
                        $string11 = /\\LMIGuardianEvt\.dll/ nocase ascii wide
                        $string12 = /\\LMIR.{0,100}\.tmp\\rarcc\.dll/ nocase ascii wide
                        $string13 = /\\LMIRescue\-.{0,100}\.clog/ nocase ascii wide
                        $string14 = /\\LMIRescue\-.{0,100}\.connlog/ nocase ascii wide
                        $string15 = /\\LMIRescueCOL\.log/ nocase ascii wide
                        $string16 = /\\LMIRescueMqttMessages_.{0,100}\.dat/ nocase ascii wide
                        $string17 = /\\LMIRescueUpdater\.log/ nocase ascii wide
                        $string18 = /\\LMIRhook\.000\.dll/ nocase ascii wide
                        $string19 = /\\lmirtechconsole\.exe/ nocase ascii wide
                        $string20 = /\\LMIRTechConsole\.exe/ nocase ascii wide
                        $string21 = /\\LMITrs\-.{0,100}\.trs/ nocase ascii wide
                        $string22 = /\\LogMeIn\sRescue\sApplet\\LMIR/ nocase ascii wide
                        $string23 = /\\LogMeIn\sRescue\sApplet\\LMIR/ nocase ascii wide
                        $string24 = /\\LogMeIn\sRescue\sAVI\sCodec\\/ nocase ascii wide
                        $string25 = /\\logmein\srescue\stechnician\sconsole\\/ nocase ascii wide
                        $string26 = /\\LogMeIn\\Dumps\\/ nocase ascii wide
                        $string27 = /\\LogMeInRescue_ipc/ nocase ascii wide
                        $string28 = /\\LogMeInRescue_rarc_r_/ nocase ascii wide
                        $string29 = /\\LogMeInRescue_rarc_w_/ nocase ascii wide
                        $string30 = /\\LogMeInRescueTechnicianConsole_x64/ nocase ascii wide
                        $string31 = /\\ProgramData\\LogMeIn\\/ nocase ascii wide
                        $string32 = /\\ractrlkeyhook\.dll/ nocase ascii wide
                        $string33 = /\\RescueWinRTLib\.dll/ nocase ascii wide
                        $string34 = /\\RescueWinRTLib\.dll/ nocase ascii wide
                        $string35 = /\\Root\\InventoryApplicationFile\\support\-logmeinr/ nocase ascii wide
                        $string36 = /\\RunOnce\\.{0,100}LogMeInRescue_/ nocase ascii wide
                        $string37 = /\\Software\\LogMeInRescue\\/ nocase ascii wide
                        $string38 = /\\Start\sMenu\\Programs\\LogMeIn\sRescue\\/ nocase ascii wide
                        $string39 = /\\Start\sMenu\\Programs\\LogMeIn/ nocase ascii wide
                        $string40 = /\<Data\>LogMeIn\,\sInc\.\<\/Data\>/ nocase ascii wide
                        $string41 = "9d2ce0345f4ee5798a49a8a13e33c7502a2ac655" nocase ascii wide
                        $string42 = /control\..{0,100}\.logmeinrescue\.com/ nocase ascii wide
                        $string43 = /control\.rsc\-app.{0,100}\.logmeinrescue\.com/ nocase ascii wide
                        $string44 = /https\:\/\/secure\.logmeinrescue\.com\/R\?i\=2\&Code\=/ nocase ascii wide
                        $string45 = /https\:\/\/secure\.logmeinrescue\.com\/TechnicianConsole\/Launch/ nocase ascii wide
                        $string46 = /LMI_RescueRC\.exe/ nocase ascii wide
                        $string47 = /LMIGuardianDll\.dll/ nocase ascii wide
                        $string48 = /LMIGuardianSvc\.exe/ nocase ascii wide
                        $string49 = /LogMeIn\sRescue\sTechnician\sConsole\.lnk/ nocase ascii wide
                        $string50 = /LogMeInRescueTechnicianConsoleApp\.msi/ nocase ascii wide
                        $string51 = /Support\-LogMeInRescue\.exe/ nocase ascii wide
                        $string52 = /Support\-LogMeInRescue\.exe/ nocase ascii wide
                        $string53 = /SUPPORT\-LOGMEINRESCUE\.EXE\-/ nocase ascii wide
                        $string54 = /turn\.console\.gotoassist\.com/ nocase ascii wide
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