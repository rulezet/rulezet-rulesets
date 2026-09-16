rule KittyStager
{
    meta:
        description = "Detection patterns for the tool 'KittyStager' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KittyStager"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " KittyStager" nocase ascii wide
                        $string2 = "/edr-checker/" nocase ascii wide
                        $string3 = "/getLegit/cdnl" nocase ascii wide
                        $string4 = "/getLegit/grkg" nocase ascii wide
                        $string5 = "/getLegit/prvw" nocase ascii wide
                        $string6 = "/getLegit/qhwl" nocase ascii wide
                        $string7 = "/getLegit/tsom" nocase ascii wide
                        $string8 = "/getLegit/zijz" nocase ascii wide
                        $string9 = "/kittens/haloKitten" nocase ascii wide
                        $string10 = "/kittens/recycleKitten" nocase ascii wide
                        $string11 = "/KittyStager/" nocase ascii wide
                        $string12 = "/postLegit/grkg" nocase ascii wide
                        $string13 = "/postLegit/qhwl" nocase ascii wide
                        $string14 = /\/shellcode.{0,100}loader\.bin/ nocase ascii wide
                        $string15 = /\\basicKitten\.exe/ nocase ascii wide
                        $string16 = /\\kitten\.exe/ nocase ascii wide
                        $string17 = /\\KittyStager/ nocase ascii wide
                        $string18 = /127\.0\.0\.1\:1337/ nocase ascii wide
                        $string19 = "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3" nocase ascii wide
                        $string20 = /bananaKitten\.exe/ nocase ascii wide
                        $string21 = /dllKitten\.dll/ nocase ascii wide
                        $string22 = "Enelg52/KittyStager" nocase ascii wide
                        $string23 = /Invoke\-EDRChecker\.ps1/ nocase ascii wide
                        $string24 = /kitten\.dll/ nocase ascii wide
                        $string25 = "kitten/basicKitten" nocase ascii wide
                        $string26 = /kitten_test\.go/ nocase ascii wide
                        $string27 = "kittens/bananaKitten" nocase ascii wide
                        $string28 = "KittyStager -" nocase ascii wide
                        $string29 = /KittyStager\s\?/ nocase ascii wide
                        $string30 = /KittyStager\s\?\?/ nocase ascii wide
                        $string31 = /KittyStager\.git/ nocase ascii wide
                        $string32 = "KittyStager/cmd" nocase ascii wide
                        $string33 = "KittyStager/internal" nocase ascii wide
                        $string34 = "KittyStager/kitten" nocase ascii wide
                        $string35 = "localhost:1337" nocase ascii wide
                        $string36 = /malware\.NewConfig/ nocase ascii wide
                        $string37 = /\-o\s\skitten\.exe/ nocase ascii wide
                        $string38 = /output.{0,100}kitten\.exe/ nocase ascii wide
                        $string39 = /shellcode.{0,100}shellcode\.bin/ nocase ascii wide
                        $string40 = "xzfbmR6MskR8J6Zr58RrhMc325kejLJE" nocase ascii wide
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