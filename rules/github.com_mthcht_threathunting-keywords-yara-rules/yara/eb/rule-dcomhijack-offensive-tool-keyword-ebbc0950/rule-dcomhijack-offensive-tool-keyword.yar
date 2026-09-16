rule rule_dcomhijack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dcomhijack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dcomhijack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.cna/ nocase ascii wide
                        $string2_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.git/ nocase ascii wide
                        $string3_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.git/ nocase ascii wide
                        $string4_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.py/ nocase ascii wide
                        $string5_dcomhijack_offensive_tool_keyword = /\\dcomhijack\.py/ nocase ascii wide
                        $string6_dcomhijack_offensive_tool_keyword = "2fe3e062aad09c372500bdef858a32344d95c7b8036d4cb5f0091a2db17b446f" nocase ascii wide
                        $string7_dcomhijack_offensive_tool_keyword = "9f1186262760c8424674045530bb64d541acbd5a5364e5e56f23cae01243a59e" nocase ascii wide
                        $string8_dcomhijack_offensive_tool_keyword = /dcomhijack\.cna/ nocase ascii wide
                        $string9_dcomhijack_offensive_tool_keyword = /dcomhijack\.py\s\-object\s/ nocase ascii wide
                        $string10_dcomhijack_offensive_tool_keyword = /dcomhijack\.py/ nocase ascii wide
                        $string11_dcomhijack_offensive_tool_keyword = "dcomhijack-main" nocase ascii wide
                        $string12_dcomhijack_offensive_tool_keyword = /upload\-dll\s.{0,100}\s.{0,100}\.dll/ nocase ascii wide
                        $string13_dcomhijack_offensive_tool_keyword = "WKL-Sec/dcomhijack" nocase ascii wide
                        $string14_dcomhijack_offensive_tool_keyword = "WKL-Sec/dcomhijack" nocase ascii wide
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