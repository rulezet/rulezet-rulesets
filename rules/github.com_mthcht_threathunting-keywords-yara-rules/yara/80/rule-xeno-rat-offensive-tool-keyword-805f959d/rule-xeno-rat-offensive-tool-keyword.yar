rule rule_xeno_rat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xeno-rat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xeno-rat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_xeno_rat_offensive_tool_keyword = /\/xeno\-rat\.git/ nocase ascii wide
                        $string2_xeno_rat_offensive_tool_keyword = /\\CurrentVersion\\Run\\XenoUpdateManager/ nocase ascii wide
                        $string3_xeno_rat_offensive_tool_keyword = /\\InfoGrab\.dll/ nocase ascii wide
                        $string4_xeno_rat_offensive_tool_keyword = /\\keyLogger\.cs/ nocase ascii wide
                        $string5_xeno_rat_offensive_tool_keyword = /\\KeyLoggerOffline\./ nocase ascii wide
                        $string6_xeno_rat_offensive_tool_keyword = /\\LiveMicrophone\.dll/ nocase ascii wide
                        $string7_xeno_rat_offensive_tool_keyword = /\\OfflineKeyloggerPipe/ nocase ascii wide
                        $string8_xeno_rat_offensive_tool_keyword = /\\Programs\\StartUp\\XenoUpdateManager/ nocase ascii wide
                        $string9_xeno_rat_offensive_tool_keyword = /\\ReverseProxy\.dll/ nocase ascii wide
                        $string10_xeno_rat_offensive_tool_keyword = /\\xeno\srat\sserver\./ nocase ascii wide
                        $string11_xeno_rat_offensive_tool_keyword = /\\xeno\srat\sserver\\/ nocase ascii wide
                        $string12_xeno_rat_offensive_tool_keyword = /\\xeno\-rat\\/ nocase ascii wide
                        $string13_xeno_rat_offensive_tool_keyword = /\\xeno\-rat\-main/ nocase ascii wide
                        $string14_xeno_rat_offensive_tool_keyword = "06B2B14A-CE87-41C0-A77A-2644FE3231C7" nocase ascii wide
                        $string15_xeno_rat_offensive_tool_keyword = "13A59BB8-0246-4FFA-951B-89B9A341F159" nocase ascii wide
                        $string16_xeno_rat_offensive_tool_keyword = "310FC5BE-6F5E-479C-A246-6093A39296C0" nocase ascii wide
                        $string17_xeno_rat_offensive_tool_keyword = "4F169EA5-8854-4258-9D2C-D44F37D88776" nocase ascii wide
                        $string18_xeno_rat_offensive_tool_keyword = "534D9A24-3138-4209-A4C6-6B9C1EF0B579" nocase ascii wide
                        $string19_xeno_rat_offensive_tool_keyword = "644AFE4A-2267-4DF9-A79D-B514FB31830E" nocase ascii wide
                        $string20_xeno_rat_offensive_tool_keyword = "70795D10-8ADF-4A4D-A584-9AB1BBF40D4B" nocase ascii wide
                        $string21_xeno_rat_offensive_tool_keyword = "8493D0F0-CA01-4C5A-A6E3-C0F427966ABD" nocase ascii wide
                        $string22_xeno_rat_offensive_tool_keyword = "8A15D28C-252A-4FCC-8BBD-BC3802C0320A" nocase ascii wide
                        $string23_xeno_rat_offensive_tool_keyword = "8B605B2E-AAD2-46FB-A348-27E3AABA4C9C" nocase ascii wide
                        $string24_xeno_rat_offensive_tool_keyword = "9CCE5C71-14B4-4A08-958D-4E593975658B" nocase ascii wide
                        $string25_xeno_rat_offensive_tool_keyword = "A138FC2A-7BFF-4B3C-94A0-62A8BC01E8C0" nocase ascii wide
                        $string26_xeno_rat_offensive_tool_keyword = "A64EF001-BE90-4CF5-86B2-22DFDB49AE81" nocase ascii wide
                        $string27_xeno_rat_offensive_tool_keyword = "A9EAA820-EC72-4052-80D0-A2CCBFCC83E6" nocase ascii wide
                        $string28_xeno_rat_offensive_tool_keyword = "C346B912-51F2-4A2E-ACC3-0AC2D28920C6" nocase ascii wide
                        $string29_xeno_rat_offensive_tool_keyword = "C373A937-312C-4C8D-BD04-BAAF568337E7" nocase ascii wide
                        $string30_xeno_rat_offensive_tool_keyword = "D3E7005E-6C5B-47F3-A0B3-028C81C0C1ED" nocase ascii wide
                        $string31_xeno_rat_offensive_tool_keyword = "F60C3246-D449-412B-A858-3B5E84494D1A" nocase ascii wide
                        $string32_xeno_rat_offensive_tool_keyword = "F61EEB46-5352-4349-B880-E4A0B38EC0DB" nocase ascii wide
                        $string33_xeno_rat_offensive_tool_keyword = /https\:\/\/t\.me\/moom825/ nocase ascii wide
                        $string34_xeno_rat_offensive_tool_keyword = /KeyLogger\.dll/ nocase ascii wide
                        $string35_xeno_rat_offensive_tool_keyword = /KeyLoggerOffline\.dll/ nocase ascii wide
                        $string36_xeno_rat_offensive_tool_keyword = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsICI=" nocase ascii wide
                        $string37_xeno_rat_offensive_tool_keyword = "moom825/xeno-rat" nocase ascii wide
                        $string38_xeno_rat_offensive_tool_keyword = /plugins\\ScreenControl\.dll/ nocase ascii wide
                        $string39_xeno_rat_offensive_tool_keyword = "Ransom:Win32/Sodinokibi" nocase ascii wide
                        $string40_xeno_rat_offensive_tool_keyword = /Uacbypass\.dll/ nocase ascii wide
                        $string41_xeno_rat_offensive_tool_keyword = /\-\-user\-data\-dir\=C\:\\\\chrome\-dev\-profile23\s\-\-remote\-debugging\-port\=9222/ nocase ascii wide
                        $string42_xeno_rat_offensive_tool_keyword = /xeno\srat\sclient\.exe/ nocase ascii wide
                        $string43_xeno_rat_offensive_tool_keyword = /xeno\srat\sserver\.exe/ nocase ascii wide
                        $string44_xeno_rat_offensive_tool_keyword = /xeno\%20rat\%20client\.exe/ nocase ascii wide
                        $string45_xeno_rat_offensive_tool_keyword = /xeno\%20rat\%20server\.exe/ nocase ascii wide
                        $string46_xeno_rat_offensive_tool_keyword = /Xeno_manager\.exe/ nocase ascii wide
                        $string47_xeno_rat_offensive_tool_keyword = /XenoUpdateManager\.lnk/ nocase ascii wide
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