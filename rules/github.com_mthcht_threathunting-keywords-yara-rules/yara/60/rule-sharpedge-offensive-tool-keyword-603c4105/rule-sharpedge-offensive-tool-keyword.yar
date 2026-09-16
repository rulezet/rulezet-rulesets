rule rule_SharpEdge_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpEdge' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEdge"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpEdge_offensive_tool_keyword = /\/SharpEdge\.exe/ nocase ascii wide
                        $string2_SharpEdge_offensive_tool_keyword = /\/SharpEdge\.git/ nocase ascii wide
                        $string3_SharpEdge_offensive_tool_keyword = /\\SharpEdge\.csproj/ nocase ascii wide
                        $string4_SharpEdge_offensive_tool_keyword = /\\SharpEdge\.exe/ nocase ascii wide
                        $string5_SharpEdge_offensive_tool_keyword = /\\SharpEdge\.sln/ nocase ascii wide
                        $string6_SharpEdge_offensive_tool_keyword = /\\SharpEdge\-master/ nocase ascii wide
                        $string7_SharpEdge_offensive_tool_keyword = "0d21ae4c38549782f8b066155b671b2a356721209a5ecaa64bba6edcc6e2f97e" nocase ascii wide
                        $string8_SharpEdge_offensive_tool_keyword = "2388c7f7f1073b922d235f675e32e1b6b8809dcef1cce1113bf712402cbad1cd" nocase ascii wide
                        $string9_SharpEdge_offensive_tool_keyword = "75f068e65a36c0dfcd7b59c00ab3a0e73f6bc07ca84091f472caada25e32cfcd" nocase ascii wide
                        $string10_SharpEdge_offensive_tool_keyword = "D116BEC7-8DEF-4FCE-BF84-C8504EF4E481" nocase ascii wide
                        $string11_SharpEdge_offensive_tool_keyword = "rvrsh3ll/SharpEdge" nocase ascii wide
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