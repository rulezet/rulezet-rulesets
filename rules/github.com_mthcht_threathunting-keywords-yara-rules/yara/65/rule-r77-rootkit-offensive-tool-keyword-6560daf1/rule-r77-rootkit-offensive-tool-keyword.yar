rule rule_r77_rootkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'r77-rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "r77-rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_r77_rootkit_offensive_tool_keyword = /\sr77\-x64\.dll/ nocase ascii wide
                        $string2_r77_rootkit_offensive_tool_keyword = /\sr77\-x86\.dll/ nocase ascii wide
                        $string3_r77_rootkit_offensive_tool_keyword = /\/r77\-rootkit\.git/ nocase ascii wide
                        $string4_r77_rootkit_offensive_tool_keyword = /\/r77\-x64\.dll/ nocase ascii wide
                        $string5_r77_rootkit_offensive_tool_keyword = /\/r77\-x86\.dll/ nocase ascii wide
                        $string6_r77_rootkit_offensive_tool_keyword = /\\\.\\pipe\\\$77childproc/ nocase ascii wide
                        $string7_r77_rootkit_offensive_tool_keyword = /\\\.\\pipe\\\$77childproc64/ nocase ascii wide
                        $string8_r77_rootkit_offensive_tool_keyword = /\\\.\\pipe\\\$77control_redirect/ nocase ascii wide
                        $string9_r77_rootkit_offensive_tool_keyword = /\\\\\.\\\\pipe\\\\\$77childproc/ nocase ascii wide
                        $string10_r77_rootkit_offensive_tool_keyword = /\\\\\.\\\\pipe\\\\\$77control_redirect/ nocase ascii wide
                        $string11_r77_rootkit_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\\$77childproc64/ nocase ascii wide
                        $string12_r77_rootkit_offensive_tool_keyword = /\\\\pipe\\\\\$77control/ nocase ascii wide
                        $string13_r77_rootkit_offensive_tool_keyword = /\\InstallShellcode\.exe/ nocase ascii wide
                        $string14_r77_rootkit_offensive_tool_keyword = /\\pipe\\\$77control/ nocase ascii wide
                        $string15_r77_rootkit_offensive_tool_keyword = /\\r77config\.c/ nocase ascii wide
                        $string16_r77_rootkit_offensive_tool_keyword = /\\r77\-rootkit\\/ nocase ascii wide
                        $string17_r77_rootkit_offensive_tool_keyword = /\\r77\-x64\.dll/ nocase ascii wide
                        $string18_r77_rootkit_offensive_tool_keyword = /\\r77\-x86\.dll/ nocase ascii wide
                        $string19_r77_rootkit_offensive_tool_keyword = "00D7268A-92A9-4CD4-ADDF-175E9BF16AE0" nocase ascii wide
                        $string20_r77_rootkit_offensive_tool_keyword = "06AF1D64-F2FC-4767-8794-7313C7BB0A40" nocase ascii wide
                        $string21_r77_rootkit_offensive_tool_keyword = "1BA54A13-B390-47B3-9628-B58A2BBA193B" nocase ascii wide
                        $string22_r77_rootkit_offensive_tool_keyword = "2D6FDD44-39B1-4FF8-8AE0-60A6B0979F5F" nocase ascii wide
                        $string23_r77_rootkit_offensive_tool_keyword = "4D71336E-6EF6-4DF1-8457-B94DC3D73FE7" nocase ascii wide
                        $string24_r77_rootkit_offensive_tool_keyword = "7271AFD1-10F6-4589-95B7-3ABF98E7B2CA" nocase ascii wide
                        $string25_r77_rootkit_offensive_tool_keyword = "78BB6D02-6E02-4933-89DC-4AD8EE0B303F" nocase ascii wide
                        $string26_r77_rootkit_offensive_tool_keyword = "86F8C733-F773-4AD8-9282-3F99953261FD" nocase ascii wide
                        $string27_r77_rootkit_offensive_tool_keyword = "addc2b1c765eb8512c2fc911e2f7dca94a51a88048ae3e2ef51b74fe955e61bc" nocase ascii wide
                        $string28_r77_rootkit_offensive_tool_keyword = "AFB848D0-68F8-42D1-A1C8-99DFBE034FCF" nocase ascii wide
                        $string29_r77_rootkit_offensive_tool_keyword = "BCE48DAE-232E-4B3D-B5B5-D0B29BB7E9DE" nocase ascii wide
                        $string30_r77_rootkit_offensive_tool_keyword = "bytecode77/r77-rootkit" nocase ascii wide
                        $string31_r77_rootkit_offensive_tool_keyword = "E3104B33-DB3D-4C83-B393-1E05E1FF2B10" nocase ascii wide
                        $string32_r77_rootkit_offensive_tool_keyword = "E55F7214-8CC4-4E1D-AEDB-C908D23902A4" nocase ascii wide
                        $string33_r77_rootkit_offensive_tool_keyword = "F0005D08-6278-4BFE-B492-F86CCEC797D5" nocase ascii wide
                        $string34_r77_rootkit_offensive_tool_keyword = /r77Rootkit\%201\.5\.2\.zip/ nocase ascii wide
                        $string35_r77_rootkit_offensive_tool_keyword = /SOFTWARE\\\$77config/ nocase ascii wide
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