rule rule_Bat_Potato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Bat-Potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bat-Potato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Bat_Potato_offensive_tool_keyword = /\sBat\-Potato\.bat/ nocase ascii wide
                        $string2_Bat_Potato_offensive_tool_keyword = /\/Bat\-Potato\.bat/ nocase ascii wide
                        $string3_Bat_Potato_offensive_tool_keyword = /\/Bat\-Potato\.git/ nocase ascii wide
                        $string4_Bat_Potato_offensive_tool_keyword = /\\Juicy\-Potato\-x86\-master/ nocase ascii wide
                        $string5_Bat_Potato_offensive_tool_keyword = "0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036" nocase ascii wide
                        $string6_Bat_Potato_offensive_tool_keyword = "0x4xel/Bat-Potato" nocase ascii wide
                        $string7_Bat_Potato_offensive_tool_keyword = "74e35d9c8f14042101ba70a5754c800de149c83d5ddfd2303f99fff92f7b4d7c" nocase ascii wide
                        $string8_Bat_Potato_offensive_tool_keyword = "878273cce2ef59c3bf4a3e4533a6b4101c9a21d57cc629cabe12ef6a05c8dda9" nocase ascii wide
                        $string9_Bat_Potato_offensive_tool_keyword = /Bat\-Potato\-main\.zip/ nocase ascii wide
                        $string10_Bat_Potato_offensive_tool_keyword = "e8d4f270bb109e0a3930dc3bf3413d8d071d283c19054809057fb9560f4daa44" nocase ascii wide
                        $string11_Bat_Potato_offensive_tool_keyword = "e8fbec25db4f9d95b5e8f41cca51a4b32be8674a4dea7a45b6f7aeb22dbc38db" nocase ascii wide
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