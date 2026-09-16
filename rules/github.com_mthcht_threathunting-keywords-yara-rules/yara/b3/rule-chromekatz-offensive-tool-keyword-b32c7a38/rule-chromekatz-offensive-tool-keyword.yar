rule rule_ChromeKatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ChromeKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ChromeKatz_offensive_tool_keyword = /\.exe\s\.\\chrome\.DMP/ nocase ascii wide
                        $string2_ChromeKatz_offensive_tool_keyword = /\.exe\s\.\\msedge\.DMP/ nocase ascii wide
                        $string3_ChromeKatz_offensive_tool_keyword = /\/ChromeKatz\.git/ nocase ascii wide
                        $string4_ChromeKatz_offensive_tool_keyword = /\\BOF\-Template\\x64\\/ nocase ascii wide
                        $string5_ChromeKatz_offensive_tool_keyword = /\\ChromeKatz\.sln/ nocase ascii wide
                        $string6_ChromeKatz_offensive_tool_keyword = /\\CookieKatz\.vcxproj/ nocase ascii wide
                        $string7_ChromeKatz_offensive_tool_keyword = /\\CookieKatz\-BOF\\/ nocase ascii wide
                        $string8_ChromeKatz_offensive_tool_keyword = /\\CookieKatzMinidump\\/ nocase ascii wide
                        $string9_ChromeKatz_offensive_tool_keyword = /\]\sNumber\sof\savailable\scredentials\:\s\%zu/ nocase ascii wide
                        $string10_ChromeKatz_offensive_tool_keyword = "002cb66d300bfb43557d4a2857db4aa75260a07feee6ec53375d0cfb6161e2bd" nocase ascii wide
                        $string11_ChromeKatz_offensive_tool_keyword = "0C81C7D4-736A-4876-A36E-15E5B2EF5117" nocase ascii wide
                        $string12_ChromeKatz_offensive_tool_keyword = "118e93d0a030df314b4e592e9470c9ae9d6c40de1417714172a95891248a2365" nocase ascii wide
                        $string13_ChromeKatz_offensive_tool_keyword = "17a1d963e1565ecff5794a685188f34adc40bc12b4f31aa32db53b6956369827" nocase ascii wide
                        $string14_ChromeKatz_offensive_tool_keyword = "17a1d963e1565ecff5794a685188f34adc40bc12b4f31aa32db53b6956369827" nocase ascii wide
                        $string15_ChromeKatz_offensive_tool_keyword = "2611455f4d60bc80f43cb13f480c6bee70497fffea48ed5c0b7d67e7fce33a52" nocase ascii wide
                        $string16_ChromeKatz_offensive_tool_keyword = "33ccc2fca462fcf743513e4f01ebe3b7302e0158a44b8dfa1f3e56b78b3ff0be" nocase ascii wide
                        $string17_ChromeKatz_offensive_tool_keyword = "33ccc2fca462fcf743513e4f01ebe3b7302e0158a44b8dfa1f3e56b78b3ff0be" nocase ascii wide
                        $string18_ChromeKatz_offensive_tool_keyword = "36a659bab7eec62733d13b9e7f8a6ae891cfaf7cd2ec36824bf41f7e6b706944" nocase ascii wide
                        $string19_ChromeKatz_offensive_tool_keyword = "65514a7171c001cd3bcc99f90efca058fe8b22ba896194eb60ea2249fbce66ee" nocase ascii wide
                        $string20_ChromeKatz_offensive_tool_keyword = "726888af98eaa956dd40e486f4fcb93d7e12880f9540d9f28aabda8f90035c1a" nocase ascii wide
                        $string21_ChromeKatz_offensive_tool_keyword = "92d262037522935fde4039ff17bdc6648c294519417e605477d78a9f0e84f20a" nocase ascii wide
                        $string22_ChromeKatz_offensive_tool_keyword = "9306e6c0e310b8146db022c3387eb9bb6076a13fb73e45ae98927b3dfb43872b" nocase ascii wide
                        $string23_ChromeKatz_offensive_tool_keyword = "a9bbb6cb0597d7f59a85f981550e52f148f023a0576434ba9396bc8f5eb3f989" nocase ascii wide
                        $string24_ChromeKatz_offensive_tool_keyword = "acd7392528b68181416263c966f899f4cd0b6430951ca09900739601c588eb5d" nocase ascii wide
                        $string25_ChromeKatz_offensive_tool_keyword = "b7554de4073bb94a00faac4f83fc081f418158073d75ac53d06af29fde8efe9d" nocase ascii wide
                        $string26_ChromeKatz_offensive_tool_keyword = "CB790E12-603E-4C7C-9DC1-14A50819AF8C" nocase ascii wide
                        $string27_ChromeKatz_offensive_tool_keyword = /ChromeKatz\/Memory\.cpp/ nocase ascii wide
                        $string28_ChromeKatz_offensive_tool_keyword = /ChromeKatz\/Process\.cpp/ nocase ascii wide
                        $string29_ChromeKatz_offensive_tool_keyword = /ChromeKatz\\Memory\.cpp/ nocase ascii wide
                        $string30_ChromeKatz_offensive_tool_keyword = /ChromeKatz\\Process\.cpp/ nocase ascii wide
                        $string31_ChromeKatz_offensive_tool_keyword = "cookie-katz chrome " nocase ascii wide
                        $string32_ChromeKatz_offensive_tool_keyword = "cookie-katz chrome " nocase ascii wide
                        $string33_ChromeKatz_offensive_tool_keyword = "cookie-katz edge " nocase ascii wide
                        $string34_ChromeKatz_offensive_tool_keyword = "CookieKatz Minidump parser" nocase ascii wide
                        $string35_ChromeKatz_offensive_tool_keyword = "CookieKatz Minidump parser" nocase ascii wide
                        $string36_ChromeKatz_offensive_tool_keyword = "cookie-katz webview " nocase ascii wide
                        $string37_ChromeKatz_offensive_tool_keyword = /CookieKatz\.exe/ nocase ascii wide
                        $string38_ChromeKatz_offensive_tool_keyword = /CookieKatzBOF\.cpp/ nocase ascii wide
                        $string39_ChromeKatz_offensive_tool_keyword = /CookieKatzBOF\.x64/ nocase ascii wide
                        $string40_ChromeKatz_offensive_tool_keyword = /CookieKatzBOF\.zip/ nocase ascii wide
                        $string41_ChromeKatz_offensive_tool_keyword = /CookieKatzMinidump\.exe/ nocase ascii wide
                        $string42_ChromeKatz_offensive_tool_keyword = "CredentialKatz" nocase ascii wide
                        $string43_ChromeKatz_offensive_tool_keyword = "d027404d259a269dc52eb697868f7e91cd32888fc9659d1851441aaa9ea3b8bd" nocase ascii wide
                        $string44_ChromeKatz_offensive_tool_keyword = "Don't use your cat's name as a password!" nocase ascii wide
                        $string45_ChromeKatz_offensive_tool_keyword = "Dump cookies from Chrome or Edge" nocase ascii wide
                        $string46_ChromeKatz_offensive_tool_keyword = "ebf94bb78b8deae210b897fd7c7da691e9fcfd215e641f28c5a0056a69e63aa6" nocase ascii wide
                        $string47_ChromeKatz_offensive_tool_keyword = "FDF5A0F3-73DA-4A8B-804F-EDD499A176EF" nocase ascii wide
                        $string48_ChromeKatz_offensive_tool_keyword = "Kittens love cookies too! >:3" nocase ascii wide
                        $string49_ChromeKatz_offensive_tool_keyword = "Meckazin/ChromeKatz" nocase ascii wide
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