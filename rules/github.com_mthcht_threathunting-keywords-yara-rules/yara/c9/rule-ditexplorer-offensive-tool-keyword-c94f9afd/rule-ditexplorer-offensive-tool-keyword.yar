rule rule_DitExplorer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DitExplorer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DitExplorer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DitExplorer_offensive_tool_keyword = /\/DitExplorer\.git/ nocase ascii wide
                        $string2_DitExplorer_offensive_tool_keyword = "/DitExplorer/releases/download/" nocase ascii wide
                        $string3_DitExplorer_offensive_tool_keyword = "/DitExplorer/releases/tag/v" nocase ascii wide
                        $string4_DitExplorer_offensive_tool_keyword = "/DitExplorer/tarball/" nocase ascii wide
                        $string5_DitExplorer_offensive_tool_keyword = "/DitExplorer/zipball/" nocase ascii wide
                        $string6_DitExplorer_offensive_tool_keyword = /\\DitExplorer\.sln/ nocase ascii wide
                        $string7_DitExplorer_offensive_tool_keyword = ">DIT Explorer<" nocase ascii wide
                        $string8_DitExplorer_offensive_tool_keyword = "29021B28-61F9-492D-BB51-7CA8889087E5" nocase ascii wide
                        $string9_DitExplorer_offensive_tool_keyword = "8714f9c15c56b5a6aebb5e90fe59a2f952df8f0759d776e851a1064f159e89a0" nocase ascii wide
                        $string10_DitExplorer_offensive_tool_keyword = "933f98396260d2400250b8bd4897ab13bf4399fa276fa1e20391a446da68b4cc" nocase ascii wide
                        $string11_DitExplorer_offensive_tool_keyword = "A71FCCEB-C1C5-4ADB-A949-462B653C2937" nocase ascii wide
                        $string12_DitExplorer_offensive_tool_keyword = "AD240C26-717F-4937-A4CD-5827BDC315E6" nocase ascii wide
                        $string13_DitExplorer_offensive_tool_keyword = "AEC0EBBA-3BE4-4B5C-8F5C-0BB8DDDA7148" nocase ascii wide
                        $string14_DitExplorer_offensive_tool_keyword = "cc9d7b88c9fe25358764727439bc55d5df36dc828b2b620b05c9b6129109588a" nocase ascii wide
                        $string15_DitExplorer_offensive_tool_keyword = "CDC4F57A-A3F7-459B-87BF-6219DADF6284" nocase ascii wide
                        $string16_DitExplorer_offensive_tool_keyword = "d044393f7a9e9536cc03cec12137074d41dd338c0182bbd8a4ca165f79f5a3d9" nocase ascii wide
                        $string17_DitExplorer_offensive_tool_keyword = "D1D4BB1C-798D-47B0-8525-061D40CB9E44" nocase ascii wide
                        $string18_DitExplorer_offensive_tool_keyword = "DIT Explorer Credential Extractor" nocase ascii wide
                        $string19_DitExplorer_offensive_tool_keyword = /DitExplorer\.Core/ nocase ascii wide
                        $string20_DitExplorer_offensive_tool_keyword = /DitExplorer\.CredentialExtraction/ nocase ascii wide
                        $string21_DitExplorer_offensive_tool_keyword = /DitExplorer\.EseInterop/ nocase ascii wide
                        $string22_DitExplorer_offensive_tool_keyword = /DitExplorer\.Ntds/ nocase ascii wide
                        $string23_DitExplorer_offensive_tool_keyword = /DitExplorer\.UI\./ nocase ascii wide
                        $string24_DitExplorer_offensive_tool_keyword = /DitExplorer\.UI\.WpfApp\.dll/ nocase ascii wide
                        $string25_DitExplorer_offensive_tool_keyword = /DitExplorer\.UI\.WpfApp\.exe/ nocase ascii wide
                        $string26_DitExplorer_offensive_tool_keyword = /DitExplorer\-v1\.0\-win64\-release\.zip/ nocase ascii wide
                        $string27_DitExplorer_offensive_tool_keyword = /DitExplorer\-v1\.0\-win64\-release\-standalone\.zip/ nocase ascii wide
                        $string28_DitExplorer_offensive_tool_keyword = "E2596512-8A36-4D48-8AA1-9791E48A16CC" nocase ascii wide
                        $string29_DitExplorer_offensive_tool_keyword = "e8467998e22a50d952a786c2ce337493cdd4d32a7e035a7af58bdc3c9b3f17ed" nocase ascii wide
                        $string30_DitExplorer_offensive_tool_keyword = "E8CA6917-CB06-4128-96CD-59676731B24A" nocase ascii wide
                        $string31_DitExplorer_offensive_tool_keyword = "f55b17e5f63a4f87b16061fc2d44c366bd5868c30104ef273e783c087d2ef3cb" nocase ascii wide
                        $string32_DitExplorer_offensive_tool_keyword = "trustedsec/DitExplorer" nocase ascii wide
                        $string33_DitExplorer_offensive_tool_keyword = /you\'ll\sneed\sthe\ssystem\skey\sof\sthe\sDC\sthat\syou\spulled\sthe\sNTDS\.dit\sfile/ nocase ascii wide
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