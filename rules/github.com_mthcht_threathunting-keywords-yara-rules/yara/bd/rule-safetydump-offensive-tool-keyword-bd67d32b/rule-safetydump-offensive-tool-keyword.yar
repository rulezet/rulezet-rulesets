rule rule_SafetyDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SafetyDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SafetyDump_offensive_tool_keyword = /\/SafetyDump\.exe/ nocase ascii wide
                        $string2_SafetyDump_offensive_tool_keyword = /\/SafetyDump\.git/ nocase ascii wide
                        $string3_SafetyDump_offensive_tool_keyword = /\\SafetyDump\.csproj/ nocase ascii wide
                        $string4_SafetyDump_offensive_tool_keyword = /\\SafetyDump\.exe/ nocase ascii wide
                        $string5_SafetyDump_offensive_tool_keyword = /\\SafetyDump\.sln/ nocase ascii wide
                        $string6_SafetyDump_offensive_tool_keyword = "738f3dce5ad63a16b2cf8b236d8d374022f121c0990e92adc214a6d03b0dc345" nocase ascii wide
                        $string7_SafetyDump_offensive_tool_keyword = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
                        $string8_SafetyDump_offensive_tool_keyword = "88888dcb2ac77d09b3c68c26f025f1e1ba9db667f3950a79a110896de297e162" nocase ascii wide
                        $string9_SafetyDump_offensive_tool_keyword = "989cb6a23ecba5fb7785a1e23b61b84c12ff45723eb98bb885905768e0a9550a" nocase ascii wide
                        $string10_SafetyDump_offensive_tool_keyword = "namespace SafetyDump" nocase ascii wide
                        $string11_SafetyDump_offensive_tool_keyword = "riskydissonance/SafetyDump" nocase ascii wide
                        $string12_SafetyDump_offensive_tool_keyword = /SafetyDump\.exe\s/ nocase ascii wide
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