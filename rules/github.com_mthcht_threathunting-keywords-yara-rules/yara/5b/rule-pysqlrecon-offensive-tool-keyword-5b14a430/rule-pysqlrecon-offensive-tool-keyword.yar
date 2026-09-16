rule rule_PySQLRecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PySQLRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PySQLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PySQLRecon_offensive_tool_keyword = /\/PySQLRecon\.git/ nocase ascii wide
                        $string2_PySQLRecon_offensive_tool_keyword = "/PySQLRecon/tarball" nocase ascii wide
                        $string3_PySQLRecon_offensive_tool_keyword = "/PySQLRecon/zipball" nocase ascii wide
                        $string4_PySQLRecon_offensive_tool_keyword = "2bcf6152e45cf60959f276a1e7482752895a5b17dc4d4a307a470c1a40284705" nocase ascii wide
                        $string5_PySQLRecon_offensive_tool_keyword = "55d72ecccc3e6bbf42653009b63e1c1e90b134714aca78dfd36ec35003bc3d76" nocase ascii wide
                        $string6_PySQLRecon_offensive_tool_keyword = "8213d434f255fbfba9d5432770a6b4ff85463271047384feba7176a301436634" nocase ascii wide
                        $string7_PySQLRecon_offensive_tool_keyword = "fde8744f64a41afea0aca93478a8e310a86dd3ac1e716bfdd6687e954ad2231e" nocase ascii wide
                        $string8_PySQLRecon_offensive_tool_keyword = "poetry run pysqlrecon" nocase ascii wide
                        $string9_PySQLRecon_offensive_tool_keyword = /pysqlrecon\.db/ nocase ascii wide
                        $string10_PySQLRecon_offensive_tool_keyword = /pysqlrecon\.lib/ nocase ascii wide
                        $string11_PySQLRecon_offensive_tool_keyword = /pysqlrecon\.logger/ nocase ascii wide
                        $string12_PySQLRecon_offensive_tool_keyword = "Tw1sm/PySQLRecon" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}