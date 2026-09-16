rule rule_litefuzz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'litefuzz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "litefuzz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_litefuzz_offensive_tool_keyword = /\.\/litefuzz\.py/
                        $string2_litefuzz_offensive_tool_keyword = "/sec-tools/litefuzz" nocase ascii wide
                        $string3_litefuzz_offensive_tool_keyword = /AcroRd32\.exe\sFUZZ/ nocase ascii wide
                        $string4_litefuzz_offensive_tool_keyword = "antiword FUZZ" nocase ascii wide
                        $string5_litefuzz_offensive_tool_keyword = "litefuzz -lk -c" nocase ascii wide
                        $string6_litefuzz_offensive_tool_keyword = "litefuzz -s -a " nocase ascii wide
                        $string7_litefuzz_offensive_tool_keyword = /litefuzz.{0,100}\s\-l\s\-c/ nocase ascii wide
                        $string8_litefuzz_offensive_tool_keyword = /litefuzz\.py\s/ nocase ascii wide
                        $string9_litefuzz_offensive_tool_keyword = /litefuzz\\fuzz\.py/ nocase ascii wide
                        $string10_litefuzz_offensive_tool_keyword = "--mutator N" nocase ascii wide
                        $string11_litefuzz_offensive_tool_keyword = /mutator\.py\s/ nocase ascii wide
                        $string12_litefuzz_offensive_tool_keyword = "notepad FUZZ" nocase ascii wide
                        $string13_litefuzz_offensive_tool_keyword = /puttygen\.exe\sFUZZ/ nocase ascii wide
                        $string14_litefuzz_offensive_tool_keyword = /test_litefuzz\.py/ nocase ascii wide
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