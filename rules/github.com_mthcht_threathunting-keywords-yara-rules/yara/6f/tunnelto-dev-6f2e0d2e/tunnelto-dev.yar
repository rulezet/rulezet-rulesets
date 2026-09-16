rule tunnelto_dev
{
    meta:
        description = "Detection patterns for the tool 'tunnelto.dev' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelto.dev"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install tunnelto" nocase ascii wide
                        $string2 = "\"User-Agent\", \"tunnelto-client\"" nocase ascii wide
                        $string3 = /\.\.\/tunnelto_lib/
                        $string4 = /\.tunnelto\.dev/ nocase ascii wide
                        $string5 = /\/tunnelto\.git/ nocase ascii wide
                        $string6 = "/tunnelto/releases/latest" nocase ascii wide
                        $string7 = "/tunnelto_server" nocase ascii wide
                        $string8 = "/tunnelto_server/" nocase ascii wide
                        $string9 = "/tunnelto_server:"
                        $string10 = /\@tunnelto\.dev/ nocase ascii wide
                        $string11 = /\\\.tunnelto\\key\.token/ nocase ascii wide
                        $string12 = "84a0a90cde73607684db0142f2d9cd8e636f089514eba57835ec10806d8f5f4b" nocase ascii wide
                        $string13 = "99736bcb172f9cbed127f25a80a6b91fe355c4673461878962d7b5ac94782db1" nocase ascii wide
                        $string14 = "agrinman/tap/tunnelto" nocase ascii wide
                        $string15 = "agrinman/tunnelto" nocase ascii wide
                        $string16 = "--bin tunnelto" nocase ascii wide
                        $string17 = "--bin tunnelto_server" nocase ascii wide
                        $string18 = "--bin=tunnelto" nocase ascii wide
                        $string19 = "--bin=tunnelto_server" nocase ascii wide
                        $string20 = "cb70ca2937afdb647a8716f0b0d122f71f91dd7ce777250d0d2573f0ec47c5fc" nocase ascii wide
                        $string21 = "f6e06ec835c02ff1f08cc12c77b067bce8eddd96b9015cefef250353c89e1fbd" nocase ascii wide
                        $string22 = /ghcr\.io\/agrinman\/tunnelto/ nocase ascii wide
                        $string23 = "tunnelto inspector" nocase ascii wide
                        $string24 = "tunnelto --port "
                        $string25 = "tunnelto_server/src/" nocase ascii wide
                        $string26 = /tunnelto\-linux\.tar\.gz/
                        $string27 = /tunnelto\-windows\.exe/ nocase ascii wide
                        $string28 = /wormhole\.tunnelto\.dev/ nocase ascii wide
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