rule rule_Slackor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Slackor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Slackor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Slackor_offensive_tool_keyword = /\sC\:\\Users\\Public\\build\.bat/ nocase ascii wide
                        $string2_Slackor_offensive_tool_keyword = /\sC\:\\Users\\Public\\build\.vbs/ nocase ascii wide
                        $string3_Slackor_offensive_tool_keyword = /\sC\:\\Users\\Public\\DtcInstall\.txt/ nocase ascii wide
                        $string4_Slackor_offensive_tool_keyword = /\sgoldenPac\.py\s/ nocase ascii wide
                        $string5_Slackor_offensive_tool_keyword = /\sgoldenPac\.py\s\-c\s.{0,100}\.exe/ nocase ascii wide
                        $string6_Slackor_offensive_tool_keyword = " python goldenPac " nocase ascii wide
                        $string7_Slackor_offensive_tool_keyword = /\s\-RemoveDefinitions\s\-All\sSet\-MpPreference\s\-DisableIOAVProtection\s\$true/ nocase ascii wide
                        $string8_Slackor_offensive_tool_keyword = " Set-MpPreference -DisableIOAVProtection " nocase ascii wide
                        $string9_Slackor_offensive_tool_keyword = /\%APPDATA\%\\Windows\:winrm\.vbs/ nocase ascii wide
                        $string10_Slackor_offensive_tool_keyword = /\.EXE\sMeterpreter\sReverse\sHTTP\sand\sHTTPS\sloader/ nocase ascii wide
                        $string11_Slackor_offensive_tool_keyword = /\.HTA\sloader\swith\s\.HTML\sextension\sfor\sspecific\scommand/ nocase ascii wide
                        $string12_Slackor_offensive_tool_keyword = /\/common\/beacon\.go/ nocase ascii wide
                        $string13_Slackor_offensive_tool_keyword = /\/defanger\.go/
                        $string14_Slackor_offensive_tool_keyword = /\/keyscan\.go/ nocase ascii wide
                        $string15_Slackor_offensive_tool_keyword = /\/metasploit\.go/ nocase ascii wide
                        $string16_Slackor_offensive_tool_keyword = /\/minidump\.go/ nocase ascii wide
                        $string17_Slackor_offensive_tool_keyword = /\/samdump\.go/ nocase ascii wide
                        $string18_Slackor_offensive_tool_keyword = /\/Slackor\.git/ nocase ascii wide
                        $string19_Slackor_offensive_tool_keyword = /\/Slackor\.git/ nocase ascii wide
                        $string20_Slackor_offensive_tool_keyword = "/Slackor/" nocase ascii wide
                        $string21_Slackor_offensive_tool_keyword = /\/SpookFlare\.git/ nocase ascii wide
                        $string22_Slackor_offensive_tool_keyword = /\\metasploit\.go/ nocase ascii wide
                        $string23_Slackor_offensive_tool_keyword = /\\Users\\Public\\DtcInstall\.txt/ nocase ascii wide
                        $string24_Slackor_offensive_tool_keyword = "029558a5c334d67b479885be83f0e0dc856189d1de14ad1d4136b7d451498daa" nocase ascii wide
                        $string25_Slackor_offensive_tool_keyword = "19f900f1332f1cb5895c079d90c982f7eae6cb67f989116a3cbba5101fbbe9b1" nocase ascii wide
                        $string26_Slackor_offensive_tool_keyword = "21f7c3a31ac72448d1e1aa4624672d7c3f7644fe7598ff109f2f87fd8de48cd7" nocase ascii wide
                        $string27_Slackor_offensive_tool_keyword = "23c71cff513e2be636c1084f3c8646f9601eef18b83a8010c84e824e5fd9ffba" nocase ascii wide
                        $string28_Slackor_offensive_tool_keyword = "3cc61a5e594a228e108fdbfb991ac45838ad15bf632f112cc185c356889e322d" nocase ascii wide
                        $string29_Slackor_offensive_tool_keyword = /4\.5\.6\.7\:1337/ nocase ascii wide
                        $string30_Slackor_offensive_tool_keyword = "5013e8763027aeb90e09aa70c4d29f548facb761f6c6ba6a43fe4d9ca9d58a71" nocase ascii wide
                        $string31_Slackor_offensive_tool_keyword = "535656aca26402527106fc7630aa58d64544975120b7ad1e21b91797b38db760" nocase ascii wide
                        $string32_Slackor_offensive_tool_keyword = "5872afc30ecad98baad85351941c0f0d573fed08d224d038138b7dac77ba6ea1" nocase ascii wide
                        $string33_Slackor_offensive_tool_keyword = "5d3f3909639924fe921e0ff58be252bd671db7d2c2c0cf56d301f4ea48548306" nocase ascii wide
                        $string34_Slackor_offensive_tool_keyword = "64d2905609b4275f692466d0aacdd3f9c7da7860e9ed6dd7047e6dbcec851d99" nocase ascii wide
                        $string35_Slackor_offensive_tool_keyword = "65e2792774eff8fec2ccb9280300fca6f465c06df13c4bcebb553b18c4aafc2b" nocase ascii wide
                        $string36_Slackor_offensive_tool_keyword = "74ae919aa5d393c04fd5b2a8048b8df764e871f1e652099d50c5ea63fb06a2e1" nocase ascii wide
                        $string37_Slackor_offensive_tool_keyword = "77b1042ad03c451d66b967673277d153869dafec091c3b43167c309722af44db" nocase ascii wide
                        $string38_Slackor_offensive_tool_keyword = "81b115a9e1d6c8333dbac2759eadbd56badd489ecc04eadff97217671d789776" nocase ascii wide
                        $string39_Slackor_offensive_tool_keyword = "86dc38ec63d7ddfab38fe655ac2296f328b1fcf43a070bad92cb6c1d3d721d49" nocase ascii wide
                        $string40_Slackor_offensive_tool_keyword = "9521c213fdd6e0b58f1288a67dbbc2b178233e2d46d09feb8da1727520340d48" nocase ascii wide
                        $string41_Slackor_offensive_tool_keyword = "aa3a685af2d72ed748f21a0190d6d08e226f717c8eea6b5694c2ad74a331a285" nocase ascii wide
                        $string42_Slackor_offensive_tool_keyword = /appdata.{0,100}\\Windows\:svchost\.exe/ nocase ascii wide
                        $string43_Slackor_offensive_tool_keyword = /appdata.{0,100}\\Windows\:winrm\.vbs/ nocase ascii wide
                        $string44_Slackor_offensive_tool_keyword = "Attacking domain controller " nocase ascii wide
                        $string45_Slackor_offensive_tool_keyword = "Brute forcing SIDs at " nocase ascii wide
                        $string46_Slackor_offensive_tool_keyword = "bypassuac fodhelper" nocase ascii wide
                        $string47_Slackor_offensive_tool_keyword = /C\:\\ASEC\.log/ nocase ascii wide
                        $string48_Slackor_offensive_tool_keyword = /C\:\\Users\\Public\\.{0,100}\.dmp/ nocase ascii wide
                        $string49_Slackor_offensive_tool_keyword = "c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBEQUlMWQ" nocase ascii wide
                        $string50_Slackor_offensive_tool_keyword = "c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBPTlNUQVJUIC9ydSBzeXN0ZW0" nocase ascii wide
                        $string51_Slackor_offensive_tool_keyword = "c2NodGFza3MgL2RlbGV0ZSAvVE4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC9m" nocase ascii wide
                        $string52_Slackor_offensive_tool_keyword = "c4209649986c6f8b14571e8f08553cd89046c45a1a03d1ab1b69b03d4b745eb9" nocase ascii wide
                        $string53_Slackor_offensive_tool_keyword = "c9a56e555aa154cca1e25d511e2201cc522307ca09b54346860d375447ec7929" nocase ascii wide
                        $string54_Slackor_offensive_tool_keyword = "cdd1184f3b6ee040bb0f668cb15a4691d327009942857bd0c62b11cd0e3d0f50" nocase ascii wide
                        $string55_Slackor_offensive_tool_keyword = "Coalfire-Research/Slackor" nocase ascii wide
                        $string56_Slackor_offensive_tool_keyword = "Coalfire-Research/Slackor" nocase ascii wide
                        $string57_Slackor_offensive_tool_keyword = /Could\snot\sparse\s\.dmp\sfile\swith\spypykatz/ nocase ascii wide
                        $string58_Slackor_offensive_tool_keyword = "defanger exclusion" nocase ascii wide
                        $string59_Slackor_offensive_tool_keyword = "defanger realtime" nocase ascii wide
                        $string60_Slackor_offensive_tool_keyword = "defanger signature" nocase ascii wide
                        $string61_Slackor_offensive_tool_keyword = /dist\/agent\.upx\.exe/ nocase ascii wide
                        $string62_Slackor_offensive_tool_keyword = /dist\/agent\.windows\.exe/ nocase ascii wide
                        $string63_Slackor_offensive_tool_keyword = /do_metasploit\(/ nocase ascii wide
                        $string64_Slackor_offensive_tool_keyword = "do_pyinject" nocase ascii wide
                        $string65_Slackor_offensive_tool_keyword = "Done dumping SAM hashes for host: " nocase ascii wide
                        $string66_Slackor_offensive_tool_keyword = "e6e37edd595cc04216682cda2af0ef0d0580fd3c8c808fb65df547c432ee9a43" nocase ascii wide
                        $string67_Slackor_offensive_tool_keyword = "e954e3675ef895c2a316f74b5801d9966597c35bf728020add026fc9e56473e6" nocase ascii wide
                        $string68_Slackor_offensive_tool_keyword = "e984f5efade9dcf131cc020a3c3ebf27f7b191eede39b09969be4d36a1ba9fb2" nocase ascii wide
                        $string69_Slackor_offensive_tool_keyword = "fb808cc0dbbe0b6cd1a58631befb038483fc3043175232cf7d5f9a0d29b31895" nocase ascii wide
                        $string70_Slackor_offensive_tool_keyword = "fc62634b7cdf7a2397165512a48feafc25c2f1e80d7579dfca7e8a773c58a5c3" nocase ascii wide
                        $string71_Slackor_offensive_tool_keyword = "fe8a247e683cf8041cb460365a29793bacf26f8214b82a7b44d2f8fad3b0af12" nocase ascii wide
                        $string72_Slackor_offensive_tool_keyword = "ff5a3bf00aa5f5664da20030aaafd09333f2a75830d3e7df3666d8c9fea9eaaa" nocase ascii wide
                        $string73_Slackor_offensive_tool_keyword = "Hit Slack API rate limit !!!" nocase ascii wide
                        $string74_Slackor_offensive_tool_keyword = /\'https\:\/\/slack\.com\/api\/channels\.create\'/ nocase ascii wide
                        $string75_Slackor_offensive_tool_keyword = "-just-dc-user not compatible in LOCAL mode" nocase ascii wide
                        $string76_Slackor_offensive_tool_keyword = "-just-dc-user switch is not supported in VSS mode" nocase ascii wide
                        $string77_Slackor_offensive_tool_keyword = "keyscan dump" nocase ascii wide
                        $string78_Slackor_offensive_tool_keyword = "keyscan start" nocase ascii wide
                        $string79_Slackor_offensive_tool_keyword = "keyscan stop" nocase ascii wide
                        $string80_Slackor_offensive_tool_keyword = /lsassdump\.dmp/ nocase ascii wide
                        $string81_Slackor_offensive_tool_keyword = /metasploit\.go/ nocase ascii wide
                        $string82_Slackor_offensive_tool_keyword = "n00py/Slackor" nocase ascii wide
                        $string83_Slackor_offensive_tool_keyword = "Opening PSEXEC shell at " nocase ascii wide
                        $string84_Slackor_offensive_tool_keyword = /powershell\s.{0,100}C\:\\Users\\Public\\.{0,100}\.exe.{0,100}\sforfiles\.exe\s\/p\s.{0,100}\\system32\s.{0,100}\.exe/ nocase ascii wide
                        $string85_Slackor_offensive_tool_keyword = "pypykatzClass" nocase ascii wide
                        $string86_Slackor_offensive_tool_keyword = "pypykatzfile" nocase ascii wide
                        $string87_Slackor_offensive_tool_keyword = /python\sraiseChild\.py\s\-/ nocase ascii wide
                        $string88_Slackor_offensive_tool_keyword = /raiseChild\.py\s\-target\-exec\s/ nocase ascii wide
                        $string89_Slackor_offensive_tool_keyword = /reg\.exe\ssave\sHKLM\\SAM\ssam_/ nocase ascii wide
                        $string90_Slackor_offensive_tool_keyword = /reg\.exe\ssave\sHKLM\\SECURITY\ssecurity_/ nocase ascii wide
                        $string91_Slackor_offensive_tool_keyword = /reg\.exe\ssave\sHKLM\\SYSTEM\ssys/ nocase ascii wide
                        $string92_Slackor_offensive_tool_keyword = "Requesting S4U2Proxy" nocase ascii wide
                        $string93_Slackor_offensive_tool_keyword = "Requesting S4U2self" nocase ascii wide
                        $string94_Slackor_offensive_tool_keyword = /resuming\sa\sprevious\sNTDS\.DIT\sdump\ssession\s/ nocase ascii wide
                        $string95_Slackor_offensive_tool_keyword = "SAM hashes extraction failed: " nocase ascii wide
                        $string96_Slackor_offensive_tool_keyword = /samdump\(bearer\,\scommands/ nocase ascii wide
                        $string97_Slackor_offensive_tool_keyword = /slackor\.db/ nocase ascii wide
                        $string98_Slackor_offensive_tool_keyword = /Slackor\\impacket/ nocase ascii wide
                        $string99_Slackor_offensive_tool_keyword = /spookflare\.py/ nocase ascii wide
                        $string100_Slackor_offensive_tool_keyword = /ticketer\.py\s\-nthash\s/ nocase ascii wide
                        $string101_Slackor_offensive_tool_keyword = /windows\/samdump\.go/ nocase ascii wide
                        $string102_Slackor_offensive_tool_keyword = /windows\\samdump\.go/ nocase ascii wide
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