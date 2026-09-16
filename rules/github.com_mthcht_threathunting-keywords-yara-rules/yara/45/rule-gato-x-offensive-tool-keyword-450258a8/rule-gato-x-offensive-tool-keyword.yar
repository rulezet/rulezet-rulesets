rule rule_Gato_X_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gato-X' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gato-X"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Gato_X_offensive_tool_keyword = /\/gato_x\-0\.5\.2\.tar\.gz/ nocase ascii wide
                        $string2_Gato_X_offensive_tool_keyword = /\/gato_x\-0\.5\.3\.tar\.gz/ nocase ascii wide
                        $string3_Gato_X_offensive_tool_keyword = /\/Gato\-X\.git/ nocase ascii wide
                        $string4_Gato_X_offensive_tool_keyword = "018a8c1acc14adf544c2d05b066556e7b67e3756e30e928a4ff79cde74229086" nocase ascii wide
                        $string5_Gato_X_offensive_tool_keyword = "061425625f0c923443e3329439f21d03796f26b41c1b0e3628a2ea564ff733e8" nocase ascii wide
                        $string6_Gato_X_offensive_tool_keyword = "2de627c776ab1a97d9ea2b3b16f63ef060cf4e0367f03861c85fec6106b2a7af" nocase ascii wide
                        $string7_Gato_X_offensive_tool_keyword = "58993d929685b240f375125ce5ad0540f57f6eed29b6feebaff194c061119052" nocase ascii wide
                        $string8_Gato_X_offensive_tool_keyword = "5905bf979bb3d714c2641502161d807723fc79cfc9b58cbe2a95882f12623778" nocase ascii wide
                        $string9_Gato_X_offensive_tool_keyword = "76e94a8b2541bd3c626fa5ac014d78665088f69c3b95925ea4211e68827fa1c0" nocase ascii wide
                        $string10_Gato_X_offensive_tool_keyword = "a3cb4dc05b5c42059a88e8bce99878c5228bb139b7bd3e2b36588d9ce4968141" nocase ascii wide
                        $string11_Gato_X_offensive_tool_keyword = "a5789291ca04f1490a7b9478a9b8e1c37b594a59a101fd63d17a3eea11d04cd8" nocase ascii wide
                        $string12_Gato_X_offensive_tool_keyword = "adnanekhan/Gato-X" nocase ascii wide
                        $string13_Gato_X_offensive_tool_keyword = "b7a5527f8a5f361fc787facc955937ea2294a883a63e5ad4abf1c9ed26b49ccd" nocase ascii wide
                        $string14_Gato_X_offensive_tool_keyword = "bb2dae47e442008e774626bfaa7fdeaec3eb2bacdf307d547b3205e2ecad3513" nocase ascii wide
                        $string15_Gato_X_offensive_tool_keyword = "be7732144c35e08d90a04d6d668c29b4341a44428b3d9c08ae69865bd3b97f17" nocase ascii wide
                        $string16_Gato_X_offensive_tool_keyword = "f71501c6dbf8e31c30fabed0786fa3145af0e8862712f5803c0c4177fb8d1836" nocase ascii wide
                        $string17_Gato_X_offensive_tool_keyword = /from\sgatox\.attack\.attack\simport\s/ nocase ascii wide
                        $string18_Gato_X_offensive_tool_keyword = /from\sgatox\.attack\.cicd_attack\simport\s/ nocase ascii wide
                        $string19_Gato_X_offensive_tool_keyword = /from\sgatox\.cli\simport\scli/ nocase ascii wide
                        $string20_Gato_X_offensive_tool_keyword = /from\sgatox\.cli\.output\simport\s/ nocase ascii wide
                        $string21_Gato_X_offensive_tool_keyword = /from\sgatox\.github\.api\simport\s/ nocase ascii wide
                        $string22_Gato_X_offensive_tool_keyword = /gato_x\-0\.5\.3\-py3\-none\-any\.whl/ nocase ascii wide
                        $string23_Gato_X_offensive_tool_keyword = "gato-x attack " nocase ascii wide
                        $string24_Gato_X_offensive_tool_keyword = "gato-x enum " nocase ascii wide
                        $string25_Gato_X_offensive_tool_keyword = "gato-x search " nocase ascii wide
                        $string26_Gato_X_offensive_tool_keyword = /gatox\.cli\.search/ nocase ascii wide
                        $string27_Gato_X_offensive_tool_keyword = /gatox\.enumerate\.reports\.report/ nocase ascii wide
                        $string28_Gato_X_offensive_tool_keyword = /gatox\.git\.utils\.subprocess\.run/ nocase ascii wide
                        $string29_Gato_X_offensive_tool_keyword = /gatox\.github\.api\.open/ nocase ascii wide
                        $string30_Gato_X_offensive_tool_keyword = /gatox\.github\.api\.requests\.post/ nocase ascii wide
                        $string31_Gato_X_offensive_tool_keyword = /gatox\.github\.search/ nocase ascii wide
                        $string32_Gato_X_offensive_tool_keyword = /https\:\/\/api\.github\.com\/orgs\/gatoxtest\// nocase ascii wide
                        $string33_Gato_X_offensive_tool_keyword = "pip install gato-x" nocase ascii wide
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