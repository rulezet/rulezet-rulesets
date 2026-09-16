rule rule_SharpMiniDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpMiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpMiniDump_offensive_tool_keyword = /\/SharpMiniDump\.git/ nocase ascii wide
                        $string2_SharpMiniDump_offensive_tool_keyword = /\\SharpMiniDump\-master/ nocase ascii wide
                        $string3_SharpMiniDump_offensive_tool_keyword = /\\Temp\\dumpert\.dmp/ nocase ascii wide
                        $string4_SharpMiniDump_offensive_tool_keyword = ">SharpMiniDump<" nocase ascii wide
                        $string5_SharpMiniDump_offensive_tool_keyword = "34cfee78a17d917fabf8d9a2b48fb55f8231c0b24a5f4197615d140d18eb9b2d" nocase ascii wide
                        $string6_SharpMiniDump_offensive_tool_keyword = "40a2c9d397f398d5faa631d6c6070174807e39962a22be143e35b7497b5c6bd7" nocase ascii wide
                        $string7_SharpMiniDump_offensive_tool_keyword = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" nocase ascii wide
                        $string8_SharpMiniDump_offensive_tool_keyword = "b4rtik/SharpMiniDump" nocase ascii wide
                        $string9_SharpMiniDump_offensive_tool_keyword = "f988bd7635bc12561e00eeb4aff027bd8014dc9b13600c8e8fb597ac9de5c3cf" nocase ascii wide
                        $string10_SharpMiniDump_offensive_tool_keyword = /SharpMiniDump\.exe/ nocase ascii wide
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