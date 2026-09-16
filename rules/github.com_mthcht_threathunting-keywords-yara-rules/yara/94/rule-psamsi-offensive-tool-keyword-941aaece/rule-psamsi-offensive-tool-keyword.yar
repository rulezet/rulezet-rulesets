rule rule_PSAmsi_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSAmsi' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAmsi"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSAmsi_offensive_tool_keyword = /\s\|\sFind\-AmsiSignatures/ nocase ascii wide
                        $string2_PSAmsi_offensive_tool_keyword = /\s\|\sTest\-ContainsAmsiSignatures/ nocase ascii wide
                        $string3_PSAmsi_offensive_tool_keyword = /\s\-ScriptString\s.{0,100}\s\-GetMinimallyObfuscated/ nocase ascii wide
                        $string4_PSAmsi_offensive_tool_keyword = /\s\-ScriptString\s.{0,100}\s\-PSAmsiScanner\s/ nocase ascii wide
                        $string5_PSAmsi_offensive_tool_keyword = /\s\-ServerUri\s.{0,100}\s\-FindAmsiSignatures/ nocase ascii wide
                        $string6_PSAmsi_offensive_tool_keyword = /\$PSAmsiScanRequests/ nocase ascii wide
                        $string7_PSAmsi_offensive_tool_keyword = /\/PSAmsi\.git/ nocase ascii wide
                        $string8_PSAmsi_offensive_tool_keyword = /\[console\]\:\:WriteLine\(\'Obfuscation\sRocks\!\'\)/ nocase ascii wide
                        $string9_PSAmsi_offensive_tool_keyword = "051d5f7fb8c577932d243da40e744e1e228d5f1b89c83613aa4e8a8ad5ee6b98" nocase ascii wide
                        $string10_PSAmsi_offensive_tool_keyword = "068accaf38e4552f7b761845066b901afca8590c1bdcb66d639d52541a20a79c" nocase ascii wide
                        $string11_PSAmsi_offensive_tool_keyword = "2555b58b1d822f73a540ad15f6d6b8a7105f66a7c00233bdd1c03c4b8cc85824" nocase ascii wide
                        $string12_PSAmsi_offensive_tool_keyword = "41b565b208250619c33cbb858758cceb6f5382d4d64448eab3b22300257adf4f" nocase ascii wide
                        $string13_PSAmsi_offensive_tool_keyword = "4a7242511d6678dc255d9f4651ea4ed2fec74f5293323c2ce6bb23956beb02a4" nocase ascii wide
                        $string14_PSAmsi_offensive_tool_keyword = "4e190d43b933586e8abdcbd64e900d02345834bc0ca314b8b8abc86b3c176bd3" nocase ascii wide
                        $string15_PSAmsi_offensive_tool_keyword = "527c7882ae3e01133e4230620d1435c40bfbd258fefc39cab74329a20fd0cf04" nocase ascii wide
                        $string16_PSAmsi_offensive_tool_keyword = "72cb6dcc8251f18f112f983804a34dc1f651c87614c18ced8a8f0ccf614bca80" nocase ascii wide
                        $string17_PSAmsi_offensive_tool_keyword = "7dea0ea9ae8fe294dbe38f27a1e718298ce411f3bcc86084741b8484276ea8a6" nocase ascii wide
                        $string18_PSAmsi_offensive_tool_keyword = "8ccf0e4161a841745e5ef8c6a2e46c48420b7eb010aa2aa3468b014e981949a5" nocase ascii wide
                        $string19_PSAmsi_offensive_tool_keyword = "93308034f5c3b6c30fa3251382e31f270606f94cb81bcb028edb7d68cd87e73c" nocase ascii wide
                        $string20_PSAmsi_offensive_tool_keyword = "9b432d28fab76406a94c7b59e20a71cd65d1bde26b41bcd6d31e02387e8e81cf" nocase ascii wide
                        $string21_PSAmsi_offensive_tool_keyword = "a9489baffe0c884e3ef759f05124e99864b3d4072c7011e71522a1197ed309a9" nocase ascii wide
                        $string22_PSAmsi_offensive_tool_keyword = "b626dc080fa41c23cf358fae12dfe70ed167a78b9173ae0249d4c02b7fadb34b" nocase ascii wide
                        $string23_PSAmsi_offensive_tool_keyword = "cobbr/PSAmsi" nocase ascii wide
                        $string24_PSAmsi_offensive_tool_keyword = "dfdb8a1bfa8b93e9c81e8682c57ad011d477ef756de6a97151415059b81f6270" nocase ascii wide
                        $string25_PSAmsi_offensive_tool_keyword = "e53f158d-8aa2-8c53-da89-ab75d32c8c01" nocase ascii wide
                        $string26_PSAmsi_offensive_tool_keyword = "Find-AmsiAstSignatures " nocase ascii wide
                        $string27_PSAmsi_offensive_tool_keyword = "Find-AmsiPSTokenSignatures " nocase ascii wide
                        $string28_PSAmsi_offensive_tool_keyword = /Find\-AmsiSignatures\.ps1/ nocase ascii wide
                        $string29_PSAmsi_offensive_tool_keyword = "Get-MinimallyObfuscated -ScriptPath " nocase ascii wide
                        $string30_PSAmsi_offensive_tool_keyword = "Get-PSAmsiScanResult " nocase ascii wide
                        $string31_PSAmsi_offensive_tool_keyword = "Invoke-PSAmsiScan" nocase ascii wide
                        $string32_PSAmsi_offensive_tool_keyword = "New-PSAmsiScanner -" nocase ascii wide
                        $string33_PSAmsi_offensive_tool_keyword = /\'Obfu\'\+\'scation\sRo\'\+\'cks\!\'/ nocase ascii wide
                        $string34_PSAmsi_offensive_tool_keyword = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
                        $string35_PSAmsi_offensive_tool_keyword = /Out\-ObfuscatedStringCommand\.ps1/ nocase ascii wide
                        $string36_PSAmsi_offensive_tool_keyword = /Out\-ObfuscatedTokenCommand\.ps1/ nocase ascii wide
                        $string37_PSAmsi_offensive_tool_keyword = /PowerShellObfuscator\.ps1/ nocase ascii wide
                        $string38_PSAmsi_offensive_tool_keyword = /PSAmsiClient\.ps1/ nocase ascii wide
                        $string39_PSAmsi_offensive_tool_keyword = /PSAmsiScanner\.ps1/ nocase ascii wide
                        $string40_PSAmsi_offensive_tool_keyword = "Reset-PSAmsiScanCache " nocase ascii wide
                        $string41_PSAmsi_offensive_tool_keyword = /Start\-PSAmsiClient\.ps1/ nocase ascii wide
                        $string42_PSAmsi_offensive_tool_keyword = "Start-PSAmsiServer -" nocase ascii wide
                        $string43_PSAmsi_offensive_tool_keyword = /Start\-PSAmsiServer\.ps1/ nocase ascii wide
                        $string44_PSAmsi_offensive_tool_keyword = "Test-ContainsAmsiAstSignatures " nocase ascii wide
                        $string45_PSAmsi_offensive_tool_keyword = "Test-ContainsAmsiPSTokenSignatures -" nocase ascii wide
                        $string46_PSAmsi_offensive_tool_keyword = "Test-ContainsAmsiSignatures " nocase ascii wide
                        $string47_PSAmsi_offensive_tool_keyword = /Write\-Host\s\(\'Hel\'\+\'lo\sWo\'\+\'rld\!\'\)/ nocase ascii wide
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