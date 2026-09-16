rule rule_NoArgs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NoArgs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoArgs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NoArgs_offensive_tool_keyword = /\/NoArgs\.exe/ nocase ascii wide
                        $string2_NoArgs_offensive_tool_keyword = /\/NoArgs\.git/ nocase ascii wide
                        $string3_NoArgs_offensive_tool_keyword = /\[i\]\sArgument\sSpoofed\./ nocase ascii wide
                        $string4_NoArgs_offensive_tool_keyword = /\\NoArgs\.cpp/ nocase ascii wide
                        $string5_NoArgs_offensive_tool_keyword = /\\NoArgs\.exe/ nocase ascii wide
                        $string6_NoArgs_offensive_tool_keyword = /\\NoArgs\.exe\.config/ nocase ascii wide
                        $string7_NoArgs_offensive_tool_keyword = /\\NoArgs\.exe\.log/ nocase ascii wide
                        $string8_NoArgs_offensive_tool_keyword = /\\NoArgs_Encrypted\.exe/ nocase ascii wide
                        $string9_NoArgs_offensive_tool_keyword = "6a14782fd71e08ded40b8652783cb49695b09e4abbaaf8c22cc22d582032191f" nocase ascii wide
                        $string10_NoArgs_offensive_tool_keyword = "8c7d64cec00aafa23884f1bb28337ef6ce49f2f90605800217f635526e38541d" nocase ascii wide
                        $string11_NoArgs_offensive_tool_keyword = "oh-az/NoArgs" nocase ascii wide
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