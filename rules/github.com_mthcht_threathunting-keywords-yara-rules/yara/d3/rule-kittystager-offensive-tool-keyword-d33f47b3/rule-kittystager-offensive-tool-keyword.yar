rule rule_KittyStager_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KittyStager' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KittyStager"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KittyStager_offensive_tool_keyword = " KittyStager" nocase ascii wide
                        $string2_KittyStager_offensive_tool_keyword = "/edr-checker/" nocase ascii wide
                        $string3_KittyStager_offensive_tool_keyword = "/getLegit/cdnl" nocase ascii wide
                        $string4_KittyStager_offensive_tool_keyword = "/getLegit/grkg" nocase ascii wide
                        $string5_KittyStager_offensive_tool_keyword = "/getLegit/prvw" nocase ascii wide
                        $string6_KittyStager_offensive_tool_keyword = "/getLegit/qhwl" nocase ascii wide
                        $string7_KittyStager_offensive_tool_keyword = "/getLegit/tsom" nocase ascii wide
                        $string8_KittyStager_offensive_tool_keyword = "/getLegit/zijz" nocase ascii wide
                        $string9_KittyStager_offensive_tool_keyword = "/kittens/haloKitten" nocase ascii wide
                        $string10_KittyStager_offensive_tool_keyword = "/kittens/recycleKitten" nocase ascii wide
                        $string11_KittyStager_offensive_tool_keyword = "/KittyStager/" nocase ascii wide
                        $string12_KittyStager_offensive_tool_keyword = "/postLegit/grkg" nocase ascii wide
                        $string13_KittyStager_offensive_tool_keyword = "/postLegit/qhwl" nocase ascii wide
                        $string14_KittyStager_offensive_tool_keyword = /\/shellcode.{0,100}loader\.bin/ nocase ascii wide
                        $string15_KittyStager_offensive_tool_keyword = /\\basicKitten\.exe/ nocase ascii wide
                        $string16_KittyStager_offensive_tool_keyword = /\\kitten\.exe/ nocase ascii wide
                        $string17_KittyStager_offensive_tool_keyword = /\\KittyStager/ nocase ascii wide
                        $string18_KittyStager_offensive_tool_keyword = /127\.0\.0\.1\:1337/ nocase ascii wide
                        $string19_KittyStager_offensive_tool_keyword = "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3" nocase ascii wide
                        $string20_KittyStager_offensive_tool_keyword = /bananaKitten\.exe/ nocase ascii wide
                        $string21_KittyStager_offensive_tool_keyword = /dllKitten\.dll/ nocase ascii wide
                        $string22_KittyStager_offensive_tool_keyword = "Enelg52/KittyStager" nocase ascii wide
                        $string23_KittyStager_offensive_tool_keyword = /Invoke\-EDRChecker\.ps1/ nocase ascii wide
                        $string24_KittyStager_offensive_tool_keyword = /kitten\.dll/ nocase ascii wide
                        $string25_KittyStager_offensive_tool_keyword = "kitten/basicKitten" nocase ascii wide
                        $string26_KittyStager_offensive_tool_keyword = /kitten_test\.go/ nocase ascii wide
                        $string27_KittyStager_offensive_tool_keyword = "kittens/bananaKitten" nocase ascii wide
                        $string28_KittyStager_offensive_tool_keyword = "KittyStager -" nocase ascii wide
                        $string29_KittyStager_offensive_tool_keyword = /KittyStager\s\?/ nocase ascii wide
                        $string30_KittyStager_offensive_tool_keyword = /KittyStager\s\?\?/ nocase ascii wide
                        $string31_KittyStager_offensive_tool_keyword = /KittyStager\.git/ nocase ascii wide
                        $string32_KittyStager_offensive_tool_keyword = "KittyStager/cmd" nocase ascii wide
                        $string33_KittyStager_offensive_tool_keyword = "KittyStager/internal" nocase ascii wide
                        $string34_KittyStager_offensive_tool_keyword = "KittyStager/kitten" nocase ascii wide
                        $string35_KittyStager_offensive_tool_keyword = "localhost:1337" nocase ascii wide
                        $string36_KittyStager_offensive_tool_keyword = /malware\.NewConfig/ nocase ascii wide
                        $string37_KittyStager_offensive_tool_keyword = /\-o\s\skitten\.exe/ nocase ascii wide
                        $string38_KittyStager_offensive_tool_keyword = /output.{0,100}kitten\.exe/ nocase ascii wide
                        $string39_KittyStager_offensive_tool_keyword = /shellcode.{0,100}shellcode\.bin/ nocase ascii wide
                        $string40_KittyStager_offensive_tool_keyword = "xzfbmR6MskR8J6Zr58RrhMc325kejLJE" nocase ascii wide
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