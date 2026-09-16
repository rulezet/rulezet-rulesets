rule rule_MakeMeAdmin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MakeMeAdmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MakeMeAdmin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MakeMeAdmin_offensive_tool_keyword = /\/MakeMeAdmin\s.{0,100}\sx64\.msi/ nocase ascii wide
                        $string2_MakeMeAdmin_offensive_tool_keyword = /\/MakeMeAdmin\.git/ nocase ascii wide
                        $string3_MakeMeAdmin_offensive_tool_keyword = "/MakeMeAdmin/tarball" nocase ascii wide
                        $string4_MakeMeAdmin_offensive_tool_keyword = /\/MakeMeAdmin\/tree\/v.{0,100}\/Installers/ nocase ascii wide
                        $string5_MakeMeAdmin_offensive_tool_keyword = "/MakeMeAdmin/zipball" nocase ascii wide
                        $string6_MakeMeAdmin_offensive_tool_keyword = /\\MakeMeAdmin\s.{0,100}\sx64\sDebug\.msi/ nocase ascii wide
                        $string7_MakeMeAdmin_offensive_tool_keyword = /\\MakeMeAdmin\s.{0,100}\sx64\.msi/ nocase ascii wide
                        $string8_MakeMeAdmin_offensive_tool_keyword = /\\MakeMeAdmin\.sln/ nocase ascii wide
                        $string9_MakeMeAdmin_offensive_tool_keyword = /\\MakeMeAdmin\-main/ nocase ascii wide
                        $string10_MakeMeAdmin_offensive_tool_keyword = /\\SOFTWARE\\Policies\\Sinclair\sCommunity\sCollege\\Make\sMe\sAdmin/ nocase ascii wide
                        $string11_MakeMeAdmin_offensive_tool_keyword = /\\SOFTWARE\\Sinclair\sCommunity\sCollege\\Make\sMe\sAdmin/ nocase ascii wide
                        $string12_MakeMeAdmin_offensive_tool_keyword = /\>Enables\susers\sto\selevate\sthemselves\sto\sadministrator\-level\srights\.\</ nocase ascii wide
                        $string13_MakeMeAdmin_offensive_tool_keyword = ">Make Me Admin<" nocase ascii wide
                        $string14_MakeMeAdmin_offensive_tool_keyword = ">MakeMeAdmin<" nocase ascii wide
                        $string15_MakeMeAdmin_offensive_tool_keyword = "053c976a6b035d2c3daefe986d293fcb1d92ffd0f535a649ee61218c66721555" nocase ascii wide
                        $string16_MakeMeAdmin_offensive_tool_keyword = "296176cf45851a6671437cced0cbfaf3aadf9c5d717ea973f911928a36a78442" nocase ascii wide
                        $string17_MakeMeAdmin_offensive_tool_keyword = "37447f986ad651df8ea39416f5d5289fda6d3d48155e7ae257c086f9a2478de0" nocase ascii wide
                        $string18_MakeMeAdmin_offensive_tool_keyword = "416656DC-D499-498B-8ACF-6502A13EFC9E" nocase ascii wide
                        $string19_MakeMeAdmin_offensive_tool_keyword = "5FB1809B-B0FD-48E9-9E47-3CB048369433" nocase ascii wide
                        $string20_MakeMeAdmin_offensive_tool_keyword = "63CAF2AD-A016-43BD-AA27-02CB848E2067" nocase ascii wide
                        $string21_MakeMeAdmin_offensive_tool_keyword = "77612014-2E37-4E17-AAFE-9AD4F08B4263" nocase ascii wide
                        $string22_MakeMeAdmin_offensive_tool_keyword = "79c64d376c00d7ccc3d946771a009fdcc9da4f066c9457805a19d1f804597466" nocase ascii wide
                        $string23_MakeMeAdmin_offensive_tool_keyword = "8A516D69-BA38-429F-AFFE-C571B5C1E482" nocase ascii wide
                        $string24_MakeMeAdmin_offensive_tool_keyword = "8dac9832-d464-4916-b102-9efa913bdc44" nocase ascii wide
                        $string25_MakeMeAdmin_offensive_tool_keyword = "92C5208E-DE76-49F9-B022-1A558C95B6DF" nocase ascii wide
                        $string26_MakeMeAdmin_offensive_tool_keyword = "9865ed1503bfac59d77f262ec4d443bc2eef2e850120ca601d406ff8d61c8bbb" nocase ascii wide
                        $string27_MakeMeAdmin_offensive_tool_keyword = "9CFD5FA4-5AD6-463C-87E5-3F42133B5DA8" nocase ascii wide
                        $string28_MakeMeAdmin_offensive_tool_keyword = "A2107C86-7CB5-45EE-89E8-1BC7261F7762" nocase ascii wide
                        $string29_MakeMeAdmin_offensive_tool_keyword = "b5ad23ea9d77b64653171f466d8f325936a00bcc8917f6064c66ec146db8a3ba" nocase ascii wide
                        $string30_MakeMeAdmin_offensive_tool_keyword = "B84EFDD8-CEA0-4CCA-B7B8-3F8AB3A336B4" nocase ascii wide
                        $string31_MakeMeAdmin_offensive_tool_keyword = "baa689ba1163c0c06f50a93ffac5ed0e4494fef7f0091edb95fa1a76b1551a40" nocase ascii wide
                        $string32_MakeMeAdmin_offensive_tool_keyword = "bc991b30cee4be589d540e1d0f055d62072843cbe1b95b27f40b860dc5aef935" nocase ascii wide
                        $string33_MakeMeAdmin_offensive_tool_keyword = "bf05f1f8aa31c121f30b013e644b75f8ec16c23c6041140408c76d07b003738c" nocase ascii wide
                        $string34_MakeMeAdmin_offensive_tool_keyword = "D64E40BB-9DAC-4491-8406-2CA2F2853F76" nocase ascii wide
                        $string35_MakeMeAdmin_offensive_tool_keyword = "e15ab99b615fc244af70a7d6bd7e834f0851ca1da63c4f17043c80f931cc0d8a" nocase ascii wide
                        $string36_MakeMeAdmin_offensive_tool_keyword = "e5a678fe7b074f6651954aa7c3643a21bf9019b9b0d504591a7c3e21283417ff" nocase ascii wide
                        $string37_MakeMeAdmin_offensive_tool_keyword = "F5A53B43-5D6D-48EC-BC44-C0C1A0CEFA8D" nocase ascii wide
                        $string38_MakeMeAdmin_offensive_tool_keyword = /makemeadmin\.com\// nocase ascii wide
                        $string39_MakeMeAdmin_offensive_tool_keyword = /MakeMeAdminRemoteUI\.exe/ nocase ascii wide
                        $string40_MakeMeAdmin_offensive_tool_keyword = /MakeMeAdminService\.exe/ nocase ascii wide
                        $string41_MakeMeAdmin_offensive_tool_keyword = /MakeMeAdminService\.fr/ nocase ascii wide
                        $string42_MakeMeAdmin_offensive_tool_keyword = /MakeMeAdminUI\.resources\.dll/ nocase ascii wide
                        $string43_MakeMeAdmin_offensive_tool_keyword = /net\.pipe\:\/\/.{0,100}\/MakeMeAdmin\/Service\\"/ nocase ascii wide
                        $string44_MakeMeAdmin_offensive_tool_keyword = /net\.tcp\:\/\/.{0,100}\/MakeMeAdmin\/Service/ nocase ascii wide
                        $string45_MakeMeAdmin_offensive_tool_keyword = "pseymour/MakeMeAdmin" nocase ascii wide
                        $string46_MakeMeAdmin_offensive_tool_keyword = /ServiceBase\.Run\(new\sMakeMeAdminService\(/ nocase ascii wide
                        $string47_MakeMeAdmin_offensive_tool_keyword = "ServiceName = \"MakeMeAdmin\"" nocase ascii wide
                        $string48_MakeMeAdmin_offensive_tool_keyword = /SinclairCC\.MakeMeAdmin\.Properties/ nocase ascii wide
                        $string49_MakeMeAdmin_offensive_tool_keyword = /SinclairMakeMeAdmin\.adml/ nocase ascii wide
                        $string50_MakeMeAdmin_offensive_tool_keyword = /SinclairMakeMeAdmin\.admx/ nocase ascii wide
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