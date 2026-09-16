rule rule_Lastenzug_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lastenzug' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lastenzug"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Lastenzug_offensive_tool_keyword = "! This is a sample loader for Lastenzug" nocase ascii wide
                        $string2_Lastenzug_offensive_tool_keyword = /\/LastenLoader\.exe/ nocase ascii wide
                        $string3_Lastenzug_offensive_tool_keyword = /\/Lastenzug\.git/ nocase ascii wide
                        $string4_Lastenzug_offensive_tool_keyword = /\\LastenLoader\.exe/ nocase ascii wide
                        $string5_Lastenzug_offensive_tool_keyword = /127\.0\.0\.1\:1337/ nocase ascii wide
                        $string6_Lastenzug_offensive_tool_keyword = "a07f5f82857dd9e0b02b4bb90783e028ff42e80fe8286dd2c8e983db138c3820" nocase ascii wide
                        $string7_Lastenzug_offensive_tool_keyword = /bin\/LastenPIC\.bin/ nocase ascii wide
                        $string8_Lastenzug_offensive_tool_keyword = "build -o LastenServer"
                        $string9_Lastenzug_offensive_tool_keyword = "codewhitesec/Lastenzug" nocase ascii wide
                        $string10_Lastenzug_offensive_tool_keyword = "d2807b9860e0e4801cd00f45421b5bcab30c1a818f193e4a3d33be8f65c99ea0" nocase ascii wide
                        $string11_Lastenzug_offensive_tool_keyword = "LastenPIC/SpiderPIC" nocase ascii wide
                        $string12_Lastenzug_offensive_tool_keyword = "LastenServer server "
                        $string13_Lastenzug_offensive_tool_keyword = "Lastenzug - PIC Socks4a proxy by @invist" nocase ascii wide
                        $string14_Lastenzug_offensive_tool_keyword = /ws\:\/\/127\.0\.0\.1\:1339\/yolo/ nocase ascii wide
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