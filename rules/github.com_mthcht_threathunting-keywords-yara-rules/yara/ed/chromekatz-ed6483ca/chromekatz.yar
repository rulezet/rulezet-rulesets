rule ChromeKatz
{
    meta:
        description = "Detection patterns for the tool 'ChromeKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\.\\chrome\.DMP/ nocase ascii wide
                        $string2 = /\.exe\s\.\\msedge\.DMP/ nocase ascii wide
                        $string3 = /\/ChromeKatz\.git/ nocase ascii wide
                        $string4 = /\\BOF\-Template\\x64\\/ nocase ascii wide
                        $string5 = /\\ChromeKatz\.sln/ nocase ascii wide
                        $string6 = /\\CookieKatz\.vcxproj/ nocase ascii wide
                        $string7 = /\\CookieKatz\-BOF\\/ nocase ascii wide
                        $string8 = /\\CookieKatzMinidump\\/ nocase ascii wide
                        $string9 = /\]\sNumber\sof\savailable\scredentials\:\s\%zu/ nocase ascii wide
                        $string10 = "002cb66d300bfb43557d4a2857db4aa75260a07feee6ec53375d0cfb6161e2bd" nocase ascii wide
                        $string11 = "0C81C7D4-736A-4876-A36E-15E5B2EF5117" nocase ascii wide
                        $string12 = "118e93d0a030df314b4e592e9470c9ae9d6c40de1417714172a95891248a2365" nocase ascii wide
                        $string13 = "17a1d963e1565ecff5794a685188f34adc40bc12b4f31aa32db53b6956369827" nocase ascii wide
                        $string14 = "17a1d963e1565ecff5794a685188f34adc40bc12b4f31aa32db53b6956369827" nocase ascii wide
                        $string15 = "2611455f4d60bc80f43cb13f480c6bee70497fffea48ed5c0b7d67e7fce33a52" nocase ascii wide
                        $string16 = "33ccc2fca462fcf743513e4f01ebe3b7302e0158a44b8dfa1f3e56b78b3ff0be" nocase ascii wide
                        $string17 = "33ccc2fca462fcf743513e4f01ebe3b7302e0158a44b8dfa1f3e56b78b3ff0be" nocase ascii wide
                        $string18 = "36a659bab7eec62733d13b9e7f8a6ae891cfaf7cd2ec36824bf41f7e6b706944" nocase ascii wide
                        $string19 = "65514a7171c001cd3bcc99f90efca058fe8b22ba896194eb60ea2249fbce66ee" nocase ascii wide
                        $string20 = "726888af98eaa956dd40e486f4fcb93d7e12880f9540d9f28aabda8f90035c1a" nocase ascii wide
                        $string21 = "92d262037522935fde4039ff17bdc6648c294519417e605477d78a9f0e84f20a" nocase ascii wide
                        $string22 = "9306e6c0e310b8146db022c3387eb9bb6076a13fb73e45ae98927b3dfb43872b" nocase ascii wide
                        $string23 = "a9bbb6cb0597d7f59a85f981550e52f148f023a0576434ba9396bc8f5eb3f989" nocase ascii wide
                        $string24 = "acd7392528b68181416263c966f899f4cd0b6430951ca09900739601c588eb5d" nocase ascii wide
                        $string25 = "b7554de4073bb94a00faac4f83fc081f418158073d75ac53d06af29fde8efe9d" nocase ascii wide
                        $string26 = "CB790E12-603E-4C7C-9DC1-14A50819AF8C" nocase ascii wide
                        $string27 = /ChromeKatz\/Memory\.cpp/ nocase ascii wide
                        $string28 = /ChromeKatz\/Process\.cpp/ nocase ascii wide
                        $string29 = /ChromeKatz\\Memory\.cpp/ nocase ascii wide
                        $string30 = /ChromeKatz\\Process\.cpp/ nocase ascii wide
                        $string31 = "cookie-katz chrome " nocase ascii wide
                        $string32 = "cookie-katz chrome " nocase ascii wide
                        $string33 = "cookie-katz edge " nocase ascii wide
                        $string34 = "CookieKatz Minidump parser" nocase ascii wide
                        $string35 = "CookieKatz Minidump parser" nocase ascii wide
                        $string36 = "cookie-katz webview " nocase ascii wide
                        $string37 = /CookieKatz\.exe/ nocase ascii wide
                        $string38 = /CookieKatzBOF\.cpp/ nocase ascii wide
                        $string39 = /CookieKatzBOF\.x64/ nocase ascii wide
                        $string40 = /CookieKatzBOF\.zip/ nocase ascii wide
                        $string41 = /CookieKatzMinidump\.exe/ nocase ascii wide
                        $string42 = "CredentialKatz" nocase ascii wide
                        $string43 = "d027404d259a269dc52eb697868f7e91cd32888fc9659d1851441aaa9ea3b8bd" nocase ascii wide
                        $string44 = "Don't use your cat's name as a password!" nocase ascii wide
                        $string45 = "Dump cookies from Chrome or Edge" nocase ascii wide
                        $string46 = "ebf94bb78b8deae210b897fd7c7da691e9fcfd215e641f28c5a0056a69e63aa6" nocase ascii wide
                        $string47 = "FDF5A0F3-73DA-4A8B-804F-EDD499A176EF" nocase ascii wide
                        $string48 = "Kittens love cookies too! >:3" nocase ascii wide
                        $string49 = "Meckazin/ChromeKatz" nocase ascii wide

    condition:
        any of them
}