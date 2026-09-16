rule rule_XiebroC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'XiebroC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XiebroC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_XiebroC2_offensive_tool_keyword = "/TeamServer_linux "
                        $string2_XiebroC2_offensive_tool_keyword = /\/TeamServer_win\.exe/ nocase ascii wide
                        $string3_XiebroC2_offensive_tool_keyword = /\/XiebroC2\.git/ nocase ascii wide
                        $string4_XiebroC2_offensive_tool_keyword = "/XiebroC2/releases/download/" nocase ascii wide
                        $string5_XiebroC2_offensive_tool_keyword = /\[\+\]\sRootKit\sloaded\ssuccessfully\!/ nocase ascii wide
                        $string6_XiebroC2_offensive_tool_keyword = /\[\+\]\sShellcode\sinjected\,\swaiting\s60s\sfor\sthe\shook\sto\sbe\scalled/ nocase ascii wide
                        $string7_XiebroC2_offensive_tool_keyword = /\\Plugins\\Resources\\WindowsFormsApp1\.exe/ nocase ascii wide
                        $string8_XiebroC2_offensive_tool_keyword = /\\TeamServer_win\.exe/ nocase ascii wide
                        $string9_XiebroC2_offensive_tool_keyword = /\\XiebroC2\-main/ nocase ascii wide
                        $string10_XiebroC2_offensive_tool_keyword = "16091e51ca4fcdf374a839ff3b850638918915b5d04c032fffec402286daf4cb" nocase ascii wide
                        $string11_XiebroC2_offensive_tool_keyword = "38AF011B-95F8-4F42-B4B9-B1AEE328A583" nocase ascii wide
                        $string12_XiebroC2_offensive_tool_keyword = "39e848ddc5b27f5ff9be14dc925a8d2e3da39623fa02367a09a3f36732d55300" nocase ascii wide
                        $string13_XiebroC2_offensive_tool_keyword = "4B37C8BF-B1C1-4025-93C6-C3B501CBB152" nocase ascii wide
                        $string14_XiebroC2_offensive_tool_keyword = "529b3883e56855e121fb77dc6254cf1280964b9323c71f631068c3ac6be9c4cb" nocase ascii wide
                        $string15_XiebroC2_offensive_tool_keyword = "5338267c8ef94a98f32ff42a23862c5dd42a3c19a7ad3d250ff1a9f263c17974" nocase ascii wide
                        $string16_XiebroC2_offensive_tool_keyword = "5e58cd83a2f4613303713489e819e69a42109141e3c998e21bf25906b45eeb30" nocase ascii wide
                        $string17_XiebroC2_offensive_tool_keyword = "77873f1f629ff4f8635b50544849c7904db358ee87733f42f3bcb19c87da2eab" nocase ascii wide
                        $string18_XiebroC2_offensive_tool_keyword = "7b8f9e66368aa0606e480ca7b8c62cbbd2fc9ff726630f46ed45aa45e7786e62" nocase ascii wide
                        $string19_XiebroC2_offensive_tool_keyword = "7bd1a6f777a6e86907b0b3bf24cf013bb419a4fe24b9e0b2af23fce70d823c29" nocase ascii wide
                        $string20_XiebroC2_offensive_tool_keyword = "7d251c4c6b137a24214a9f58a0b88f2eedad23d0d62050f36a567b78cb2ef497" nocase ascii wide
                        $string21_XiebroC2_offensive_tool_keyword = "7f3c414abe39b6e9ab37c48d5962f421ea91971a21f3eb1a9ff1789fafc6649e" nocase ascii wide
                        $string22_XiebroC2_offensive_tool_keyword = "835b7b956f39cff5bb6e31a4fb06ba65615ae809e249b8161126e750b9fe1aae" nocase ascii wide
                        $string23_XiebroC2_offensive_tool_keyword = "8785484adcc6ef562248e172e23ebb36ab0b7b500281a56230bb102295586897" nocase ascii wide
                        $string24_XiebroC2_offensive_tool_keyword = /AddMenuItemA\(\\"Grab\sbrowser\sPasswords\\"/ nocase ascii wide
                        $string25_XiebroC2_offensive_tool_keyword = /AddMenuItemA\(\\"Pentest\\"/ nocase ascii wide
                        $string26_XiebroC2_offensive_tool_keyword = "b4239ef8e8962d393767152c150f17bc5cf0527d6fed52d489b444f46402650a" nocase ascii wide
                        $string27_XiebroC2_offensive_tool_keyword = "b92a810f34ccdcaf783067a0534be97ee2f51561ce8a07a948c887edb234dda4" nocase ascii wide
                        $string28_XiebroC2_offensive_tool_keyword = "bbafc8c3db7a42d1419f9c741f6508da43325f3993202d8955b2f9e0d2f971a9" nocase ascii wide
                        $string29_XiebroC2_offensive_tool_keyword = "bc051b7ae14e30935c4cc0090a944f420fa69cbcf66469038af5a306030b9007" nocase ascii wide
                        $string30_XiebroC2_offensive_tool_keyword = /BypassUAC\-ETV\.exe/ nocase ascii wide
                        $string31_XiebroC2_offensive_tool_keyword = "c4bb5669fe12e106bd6bb7a0fde51cf6e90d73bbd6e4143df40eb53d2f7da776" nocase ascii wide
                        $string32_XiebroC2_offensive_tool_keyword = "c79e051bb46302d29235045e7ce05e9806e52f7fdc0249a9593cd8fa01e11c35" nocase ascii wide
                        $string33_XiebroC2_offensive_tool_keyword = /chmod\s\+x\sXiebroC2MAc/
                        $string34_XiebroC2_offensive_tool_keyword = "Convert-NetToLua -infile " nocase ascii wide
                        $string35_XiebroC2_offensive_tool_keyword = /Convert\-NetToLua\.ps1/ nocase ascii wide
                        $string36_XiebroC2_offensive_tool_keyword = "d9dd9d8ef1406c7ad002253fc6e65d035037267640f44338e9468e219f95bf3b" nocase ascii wide
                        $string37_XiebroC2_offensive_tool_keyword = "f2f43c5e7b7af02097483d4ea3ccd1bf1cf2b6a558e334a3c4821522a5214b73" nocase ascii wide
                        $string38_XiebroC2_offensive_tool_keyword = "fd0c892807df56578a3beb415d800c765873ed72ab256f5cffdb5cccd086fd27" nocase ascii wide
                        $string39_XiebroC2_offensive_tool_keyword = /greentm372\@gmail\.com/ nocase ascii wide
                        $string40_XiebroC2_offensive_tool_keyword = /InlineAssembly\(\\"Plugins\\\\Scheduled\.exe/ nocase ascii wide
                        $string41_XiebroC2_offensive_tool_keyword = "INotGreen/XiebroC2" nocase ascii wide
                        $string42_XiebroC2_offensive_tool_keyword = /set\shttps_proxy\=http\:\/\/127\.0\.0\.1\:9999/ nocase ascii wide
                        $string43_XiebroC2_offensive_tool_keyword = /set\shttps_proxy\=http\:\/\/127\.0\.0\.1\:9999/ nocase ascii wide
                        $string44_XiebroC2_offensive_tool_keyword = /SharpKatz\.exe/ nocase ascii wide
                        $string45_XiebroC2_offensive_tool_keyword = /Teamserver\.exe\s\-c\sprofile\.json/ nocase ascii wide
                        $string46_XiebroC2_offensive_tool_keyword = "WINEDEBUG=-all wine XiebroC2MAc" nocase ascii wide
                        $string47_XiebroC2_offensive_tool_keyword = /XiebroC2\-main\.zip/ nocase ascii wide
                        $string48_XiebroC2_offensive_tool_keyword = /XiebroC2\-v.{0,100}\.7z/ nocase ascii wide
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