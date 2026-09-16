rule rule_pysecdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pysecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysecdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pysecdump_offensive_tool_keyword = /\/pysecdump\.git/ nocase ascii wide
                        $string2_pysecdump_offensive_tool_keyword = /\[E\]\sUnable\sto\sread\sLSA\ssecrets\.\s\sPerhaps\syou\sare\snot\sSYTEM\?/ nocase ascii wide
                        $string3_pysecdump_offensive_tool_keyword = /\\pysecdump\-master/ nocase ascii wide
                        $string4_pysecdump_offensive_tool_keyword = "342d4b1d90f163fdbce23c4bffe2fdeecb420df0472cb44a272c2a4f604f8758" nocase ascii wide
                        $string5_pysecdump_offensive_tool_keyword = "757c6b973f06e169ec2346c818f211559a084fd2adaed2e0e9e232541b62b557" nocase ascii wide
                        $string6_pysecdump_offensive_tool_keyword = "7cabf5918c2f097e102d28085a8171e98832c150aa10ddbcd1d05e8030f184ef" nocase ascii wide
                        $string7_pysecdump_offensive_tool_keyword = "a4058df23cf217a43482e2f6fa20e55ef9005d20713a6860a4974da0fe731e64" nocase ascii wide
                        $string8_pysecdump_offensive_tool_keyword = "ad7136daff93312ebb41fe388da46d2814ab6504e23b3c90b2a56a0426a558e3" nocase ascii wide
                        $string9_pysecdump_offensive_tool_keyword = /domcachedumplive\.py/ nocase ascii wide
                        $string10_pysecdump_offensive_tool_keyword = "Dump Credential Manager for all logged in users" nocase ascii wide
                        $string11_pysecdump_offensive_tool_keyword = /framework\.win32\.domcachedumplive/ nocase ascii wide
                        $string12_pysecdump_offensive_tool_keyword = /framework\.win32\.lsasecretslive/ nocase ascii wide
                        $string13_pysecdump_offensive_tool_keyword = /lsasecretslive\.py/ nocase ascii wide
                        $string14_pysecdump_offensive_tool_keyword = "pentestmonkey/pysecdump" nocase ascii wide
                        $string15_pysecdump_offensive_tool_keyword = "pysecdump -" nocase ascii wide
                        $string16_pysecdump_offensive_tool_keyword = "pysecdump v%s " nocase ascii wide
                        $string17_pysecdump_offensive_tool_keyword = /pysecdump\.exe/ nocase ascii wide
                        $string18_pysecdump_offensive_tool_keyword = /pysecdump\.py/ nocase ascii wide
                        $string19_pysecdump_offensive_tool_keyword = "pysecdump: Starting shell" nocase ascii wide
                        $string20_pysecdump_offensive_tool_keyword = "spysecdump" nocase ascii wide
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