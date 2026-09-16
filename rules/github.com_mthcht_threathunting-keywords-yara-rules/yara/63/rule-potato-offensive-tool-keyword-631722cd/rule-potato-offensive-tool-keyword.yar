rule rule_potato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "potato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_potato_offensive_tool_keyword = /\\Potato\.exe/ nocase ascii wide
                        $string2_potato_offensive_tool_keyword = /\\Potato\\obj\\Release\\Potato\.pdb/ nocase ascii wide
                        $string3_potato_offensive_tool_keyword = /127\.0\.0\.1\/C\$\/Windows\/System32\/utilman\.exe/ nocase ascii wide
                        $string4_potato_offensive_tool_keyword = "58ba7d7a43c3cbf5ffba7351a6509d04290b41ac5565735c6b6b66ffaf2daaca" nocase ascii wide
                        $string5_potato_offensive_tool_keyword = "7e21c5b9cf9cb3cc0b3c6909fdf3a7820c6feaa45e86722ed4e7a43d39aee819" nocase ascii wide
                        $string6_potato_offensive_tool_keyword = "893CC775-335D-4010-9751-D8C8E2A04048" nocase ascii wide
                        $string7_potato_offensive_tool_keyword = "c391bff39add68d2e9bd97ecfbc98850c2b80f831007df95704eedbc7e93617b" nocase ascii wide
                        $string8_potato_offensive_tool_keyword = "foxglovesec/Potato" nocase ascii wide
                        $string9_potato_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/wpad\.dat/ nocase ascii wide
                        $string10_potato_offensive_tool_keyword = /potato\.exe\s\-ip\s/ nocase ascii wide
                        $string11_potato_offensive_tool_keyword = "Starting NBNS spoofer" nocase ascii wide
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