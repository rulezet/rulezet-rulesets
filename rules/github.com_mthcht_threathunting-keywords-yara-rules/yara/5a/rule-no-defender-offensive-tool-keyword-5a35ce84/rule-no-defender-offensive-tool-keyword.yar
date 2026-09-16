rule rule_no_defender_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'no_defender' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "no_defender"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_no_defender_offensive_tool_keyword = /\/no_defender\.exe/ nocase ascii wide
                        $string2_no_defender_offensive_tool_keyword = /\/no\-defender\.git/ nocase ascii wide
                        $string3_no_defender_offensive_tool_keyword = /\/no\-defender\.sln/ nocase ascii wide
                        $string4_no_defender_offensive_tool_keyword = /\/no\-defender\.vcxproj/ nocase ascii wide
                        $string5_no_defender_offensive_tool_keyword = /\/no\-defender\-loader\.exe/ nocase ascii wide
                        $string6_no_defender_offensive_tool_keyword = /\/no\-defender\-loader\/main\.cpp/ nocase ascii wide
                        $string7_no_defender_offensive_tool_keyword = /\\no_defender\.exe/ nocase ascii wide
                        $string8_no_defender_offensive_tool_keyword = /\\no\-defender\.exe/ nocase ascii wide
                        $string9_no_defender_offensive_tool_keyword = /\\no\-defender\.sln/ nocase ascii wide
                        $string10_no_defender_offensive_tool_keyword = /\\no\-defender\.vcxproj/ nocase ascii wide
                        $string11_no_defender_offensive_tool_keyword = /\\no\-defender\-loader\.exe/ nocase ascii wide
                        $string12_no_defender_offensive_tool_keyword = /\\no\-defender\-loader\.pdb/ nocase ascii wide
                        $string13_no_defender_offensive_tool_keyword = /\\no\-defender\-loader\.vcxproj/ nocase ascii wide
                        $string14_no_defender_offensive_tool_keyword = /\\no\-defender\-loader\\main\.cpp/ nocase ascii wide
                        $string15_no_defender_offensive_tool_keyword = "176fdbab2521f29e514c62db9038532ab5b591bf7a337d192e7710daf1c39de2" nocase ascii wide
                        $string16_no_defender_offensive_tool_keyword = "32a53f3d4ecb4456372191071783bcaf9fd95ae442722202d7fd52b3da9b89d3" nocase ascii wide
                        $string17_no_defender_offensive_tool_keyword = "3CFB521D-40ED-4891-8B6C-ED0644A237C1" nocase ascii wide
                        $string18_no_defender_offensive_tool_keyword = "4193DE42-C103-45FF-A04D-0AD64616BC59" nocase ascii wide
                        $string19_no_defender_offensive_tool_keyword = "594199ae0a6e125642f438b9b09af03d2ba269259db213fdba7901b5589f2234" nocase ascii wide
                        $string20_no_defender_offensive_tool_keyword = "62d8159fd6c2b3dc8175e8bfab36369917530bca9ae2bb2e12bf5d18fbdf9896" nocase ascii wide
                        $string21_no_defender_offensive_tool_keyword = "8b38b963ce6d0b7eec0647eb5f65005bf981fa462825a75fa193260f0a53a1e8" nocase ascii wide
                        $string22_no_defender_offensive_tool_keyword = "99c32fc0bd5b4fecb91c3774095bf610066c43596b34a0228f7ef3cb6ff39e05" nocase ascii wide
                        $string23_no_defender_offensive_tool_keyword = "c0dca4eb22f84060319a2718d3987460ad74a50ce76dfeddee62aef685fd35c2" nocase ascii wide
                        $string24_no_defender_offensive_tool_keyword = "d0a965003f74317e82e25f5c479a66acb8048a470800be03f6cd8e413f5fd598" nocase ascii wide
                        $string25_no_defender_offensive_tool_keyword = "EE666120-EE4C-4D91-A545-66BEAA1830C1" nocase ascii wide
                        $string26_no_defender_offensive_tool_keyword = "es3n1n/no-defender" nocase ascii wide
                        $string27_no_defender_offensive_tool_keyword = /es3n1n\\no\-defender/ nocase ascii wide
                        $string28_no_defender_offensive_tool_keyword = /no\-defender\/dllmain\.cpp/ nocase ascii wide
                        $string29_no_defender_offensive_tool_keyword = /no\-defender\\dllmain\.cpp/ nocase ascii wide
                        $string30_no_defender_offensive_tool_keyword = "no-defender-loader --" nocase ascii wide
                        $string31_no_defender_offensive_tool_keyword = /no\-defender\-loader\.exe\s\-\-/ nocase ascii wide

    condition:
        any of them
}