rule rule_Invoke_ArgFuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ArgFuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ArgFuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_ArgFuscator_offensive_tool_keyword = /\/ArgFuscator\.zip/ nocase ascii wide
                        $string2_Invoke_ArgFuscator_offensive_tool_keyword = /\/Invoke\-ArgFuscator\.git/ nocase ascii wide
                        $string3_Invoke_ArgFuscator_offensive_tool_keyword = "/Invoke-ArgFuscator/releases/" nocase ascii wide
                        $string4_Invoke_ArgFuscator_offensive_tool_keyword = "/Invoke-ArgFuscator/tarball/" nocase ascii wide
                        $string5_Invoke_ArgFuscator_offensive_tool_keyword = "/Invoke-ArgFuscator/zipball/" nocase ascii wide
                        $string6_Invoke_ArgFuscator_offensive_tool_keyword = /\\ArgFuscator\.zip/ nocase ascii wide
                        $string7_Invoke_ArgFuscator_offensive_tool_keyword = /\\Invoke\-ArgFuscator\-main/ nocase ascii wide
                        $string8_Invoke_ArgFuscator_offensive_tool_keyword = "03269801085da5702202a4d2cd0f006bf93e63b6da69c588414380cdf3753349" nocase ascii wide
                        $string9_Invoke_ArgFuscator_offensive_tool_keyword = "0e2a30af2c626fd1f134d32daf8d615bfae7568fd43484e5f5fc489ceb0b2faf" nocase ascii wide
                        $string10_Invoke_ArgFuscator_offensive_tool_keyword = "1de467a837f7bf75b522bf34b0a2711213d73c7ca8101b4535a5bbdc94323ac7" nocase ascii wide
                        $string11_Invoke_ArgFuscator_offensive_tool_keyword = "2308bdcf6b10c8d36213bbb8afba67549558c4cd9b112493b9e9d4b7e2d365ca" nocase ascii wide
                        $string12_Invoke_ArgFuscator_offensive_tool_keyword = "2f8ed85860e64bd52c6ef3b7a4e405a9934ca78139751adb118a0074ae7ced2d" nocase ascii wide
                        $string13_Invoke_ArgFuscator_offensive_tool_keyword = "3c6843232a8479a389876f73cf69d7277ae2c7e635918699e183c062799dbd16" nocase ascii wide
                        $string14_Invoke_ArgFuscator_offensive_tool_keyword = "3e451b530ade34ae48f51aebf8db1609272ea8d1b1438cfa7c3d570e91b39bd9" nocase ascii wide
                        $string15_Invoke_ArgFuscator_offensive_tool_keyword = "457026969789119712188521674e7eb3a1cb4ab5e121b6ba80515090eea71d27" nocase ascii wide
                        $string16_Invoke_ArgFuscator_offensive_tool_keyword = "4d14760b49f084714c356b922b2889402fca1faa5145f64c4441746897fe4d7b" nocase ascii wide
                        $string17_Invoke_ArgFuscator_offensive_tool_keyword = "5d718f2a4cb244409b90df00bca8dd43b57e5892743f203f0f382eb863b1d8f4" nocase ascii wide
                        $string18_Invoke_ArgFuscator_offensive_tool_keyword = "65dd5aa4e6cc05a7bd84be96d769806dfbe19c8c0451c13445100597fe4698d0" nocase ascii wide
                        $string19_Invoke_ArgFuscator_offensive_tool_keyword = "6c4c9900e2d006a9b7dde59982905c5c6354eb8de5ceae88f1da96161756042d" nocase ascii wide
                        $string20_Invoke_ArgFuscator_offensive_tool_keyword = "7b519e14d5860852dd54139ef9bff6a52a5e400afc6cbd1b6d7bc2a75ed674e6" nocase ascii wide
                        $string21_Invoke_ArgFuscator_offensive_tool_keyword = "835544862f1683ef3996a1b9653a0daf1937d2cdd973004e4fa5003fef54a893" nocase ascii wide
                        $string22_Invoke_ArgFuscator_offensive_tool_keyword = "844d9edc-57ad-4fcc-9fd5-77a69d4bf569" nocase ascii wide
                        $string23_Invoke_ArgFuscator_offensive_tool_keyword = "94bd506457e76c837592396e349c0d2da7f783ed0d1e3f083457b4ac013286cb" nocase ascii wide
                        $string24_Invoke_ArgFuscator_offensive_tool_keyword = "a7cc4efa0b13e199acd6d09b696b7d2ff0cff7aefd420ef9e87a216a396b1e9d" nocase ascii wide
                        $string25_Invoke_ArgFuscator_offensive_tool_keyword = "a9843a81603f299fb87f371052b47798338252b58ad8ef56dfee4bf462322eb6" nocase ascii wide
                        $string26_Invoke_ArgFuscator_offensive_tool_keyword = /ArgFuscator\.net\/archive\/refs\/heads\// nocase ascii wide
                        $string27_Invoke_ArgFuscator_offensive_tool_keyword = /ArgFuscator\.net\-main/ nocase ascii wide
                        $string28_Invoke_ArgFuscator_offensive_tool_keyword = "b72782bc3e57e54fe21104feeb218779cf739eafafab30b70a0d75f89083cdcd" nocase ascii wide
                        $string29_Invoke_ArgFuscator_offensive_tool_keyword = "d21cf671b3547b844a9adbe858c032e02f68b5d475de06b92e7776cd79d9db27" nocase ascii wide
                        $string30_Invoke_ArgFuscator_offensive_tool_keyword = "Install-Module -Name Invoke-ArgFuscator" nocase ascii wide
                        $string31_Invoke_ArgFuscator_offensive_tool_keyword = "Invoke-ArgFuscator -" nocase ascii wide
                        $string32_Invoke_ArgFuscator_offensive_tool_keyword = /Invoke\-ArgFuscator\.ps1/ nocase ascii wide
                        $string33_Invoke_ArgFuscator_offensive_tool_keyword = /Invoke\-ArgFuscator\.psd1/ nocase ascii wide
                        $string34_Invoke_ArgFuscator_offensive_tool_keyword = /Invoke\-ArgFuscator\.psm1/ nocase ascii wide
                        $string35_Invoke_ArgFuscator_offensive_tool_keyword = /Invoke\-ArgFuscator\-main\.zip/ nocase ascii wide
                        $string36_Invoke_ArgFuscator_offensive_tool_keyword = /Modifiers\\CharacterInsertion\.psm1/ nocase ascii wide
                        $string37_Invoke_ArgFuscator_offensive_tool_keyword = /using\smodule\s\\"Modifiers\\FilePathTransformer\.psm1\\"/ nocase ascii wide
                        $string38_Invoke_ArgFuscator_offensive_tool_keyword = /using\smodule\s\\"Modifiers\\OptionCharSubstitution\.psm1\\"/ nocase ascii wide
                        $string39_Invoke_ArgFuscator_offensive_tool_keyword = /using\smodule\s\\"Modifiers\\QuoteInsertion\.psm1\\"/ nocase ascii wide
                        $string40_Invoke_ArgFuscator_offensive_tool_keyword = /using\smodule\s\\"Modifiers\\RandomCase\.psm1\\"/ nocase ascii wide
                        $string41_Invoke_ArgFuscator_offensive_tool_keyword = "wietze/Invoke-ArgFuscator" nocase ascii wide
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