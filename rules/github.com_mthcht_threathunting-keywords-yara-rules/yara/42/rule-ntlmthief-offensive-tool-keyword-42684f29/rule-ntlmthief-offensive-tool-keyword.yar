rule rule_NtlmThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NtlmThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NtlmThief_offensive_tool_keyword = /\/NtlmThief\.git/ nocase ascii wide
                        $string2_NtlmThief_offensive_tool_keyword = /\\NtlmThief\\/ nocase ascii wide
                        $string3_NtlmThief_offensive_tool_keyword = "12d55d1fbe1ca3c7889434234adfda1abfbd5a8aacb076026b4a94e81d696bd5" nocase ascii wide
                        $string4_NtlmThief_offensive_tool_keyword = "230184a9e6df447df04c22c92e6cb0d494d210fb6ec4b3350d16712d1e85d6b9" nocase ascii wide
                        $string5_NtlmThief_offensive_tool_keyword = "4ce98911b8e13393c58578be23e85776dbf7c95ec878b9f08748d0921855c36b" nocase ascii wide
                        $string6_NtlmThief_offensive_tool_keyword = "CD517B47-6CA1-4AC3-BC37-D8A27F2F03A0" nocase ascii wide
                        $string7_NtlmThief_offensive_tool_keyword = "MzHmO/NtlmThief" nocase ascii wide
                        $string8_NtlmThief_offensive_tool_keyword = /NtlmThief\.exe/ nocase ascii wide
                        $string9_NtlmThief_offensive_tool_keyword = /NtlmThief\.sln/ nocase ascii wide
                        $string10_NtlmThief_offensive_tool_keyword = /NtlmThief\.vcxproj/ nocase ascii wide
                        $string11_NtlmThief_offensive_tool_keyword = "NtlmThief-main" nocase ascii wide
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