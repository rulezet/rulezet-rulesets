rule PassTheChallenge
{
    meta:
        description = "Detection patterns for the tool 'PassTheChallenge' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassTheChallenge"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PassTheChallenge\.git/ nocase ascii wide
                        $string2 = /\/PassTheChallenge\/Constants\.h/
                        $string3 = /\/PassTheChallenge\/Protocol_h\.h/
                        $string4 = "/PassTheChallenge/releases/download/" nocase ascii wide
                        $string5 = /\\PassTheChallenge\\PassTheChallenge\\/ nocase ascii wide
                        $string6 = "2116E6C5-F609-4CA8-B1A1-E87B7BE770A4" nocase ascii wide
                        $string7 = "6569a4f09ccdf814bf1697e7e35975c065909df9184eb49822a34f7a029d20da" nocase ascii wide
                        $string8 = "6aa3276e8a8fafb17e99321fad558a22f628c82b1143227ffad08382dcb679ea" nocase ascii wide
                        $string9 = "8F018213-4136-4D97-9084-F0346BBED04F" nocase ascii wide
                        $string10 = "91302dd386709f514908c61d52d0e917ef6c4db866ee9f9f1b387ceb1e87cd7a" nocase ascii wide
                        $string11 = "b6de30306cf70f10d77621a839e3be534cc938cd5736cb77887d3416aac9f27b" nocase ascii wide
                        $string12 = "b6de30306cf70f10d77621a839e3be534cc938cd5736cb77887d3416aac9f27b" nocase ascii wide
                        $string13 = "c4db3b4b49d8d75696f5641276d9ae1bcb990aaec46566719a7519810deb2f98" nocase ascii wide
                        $string14 = "c4db3b4b49d8d75696f5641276d9ae1bcb990aaec46566719a7519810deb2f98" nocase ascii wide
                        $string15 = "d4bc21da22b767a22840c442dd56536e0e5ab05932aa82899a43c29d49352932" nocase ascii wide
                        $string16 = "d79a8f7e6ddf7530d9f28267e3ab74849492aae4db6facd46a3b8dd01194738f" nocase ascii wide
                        $string17 = "fe19fcf12c8c18e41b73c3888d596a488f0a31c44ed459cba6d101660bfd7e80" nocase ascii wide
                        $string18 = "fe19fcf12c8c18e41b73c3888d596a488f0a31c44ed459cba6d101660bfd7e80" nocase ascii wide
                        $string19 = "Inject module and start PtC-RPC server inside LSASS" nocase ascii wide
                        $string20 = "ly4k/PassTheChallenge" nocase ascii wide
                        $string21 = /Pass\-the\-Challenge\s\(PtC\)\s\-\sby\sOliver\sLyak\s\(ly4k\)/ nocase ascii wide
                        $string22 = /PassTheChallenge\.cpp/ nocase ascii wide
                        $string23 = /PassTheChallenge\.exe/ nocase ascii wide
                        $string24 = /PassTheChallenge\.pdb/ nocase ascii wide
                        $string25 = /PassTheChallenge\.sln/ nocase ascii wide
                        $string26 = /PassTheChallenge\.vcxproj/ nocase ascii wide
                        $string27 = "Ping the PtC-RPC server inside LSASS" nocase ascii wide
                        $string28 = /PtC\.exe\schallenge/ nocase ascii wide
                        $string29 = /PtC\.exe\scompare/ nocase ascii wide
                        $string30 = /PtC\.exe\sinject/ nocase ascii wide
                        $string31 = /PtC\.exe\snthash\s/ nocase ascii wide
                        $string32 = /PtC\.exe\sping/ nocase ascii wide
                        $string33 = /PtC\.exe\sprotect/ nocase ascii wide
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