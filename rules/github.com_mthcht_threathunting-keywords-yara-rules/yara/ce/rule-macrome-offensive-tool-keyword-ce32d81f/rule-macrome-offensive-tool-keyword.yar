rule rule_Macrome_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Macrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Macrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Macrome_offensive_tool_keyword = /\sCharSubroutine\-Macro\.xls/ nocase ascii wide
                        $string2_Macrome_offensive_tool_keyword = /\spopcalc\.bin\s/ nocase ascii wide
                        $string3_Macrome_offensive_tool_keyword = /\spopcalc64\.bin\s/ nocase ascii wide
                        $string4_Macrome_offensive_tool_keyword = /\/BaseNEncoder\.cs/ nocase ascii wide
                        $string5_Macrome_offensive_tool_keyword = /\/BIFFRecordEncryption\.cs/ nocase ascii wide
                        $string6_Macrome_offensive_tool_keyword = /\/ExcelDocWriter\.cs/ nocase ascii wide
                        $string7_Macrome_offensive_tool_keyword = /\/MacroPatterns\.cs/ nocase ascii wide
                        $string8_Macrome_offensive_tool_keyword = "/michaelweber/Macrome" nocase ascii wide
                        $string9_Macrome_offensive_tool_keyword = /\/RC4BinaryEncryption\.cs/ nocase ascii wide
                        $string10_Macrome_offensive_tool_keyword = /\/XorObfuscation\.cs/ nocase ascii wide
                        $string11_Macrome_offensive_tool_keyword = /b2xtranslator\.xls\.csproj/ nocase ascii wide
                        $string12_Macrome_offensive_tool_keyword = /decoy_document\.xls/ nocase ascii wide
                        $string13_Macrome_offensive_tool_keyword = /Macrome\s.{0,100}\-\-decoy\-document/ nocase ascii wide
                        $string14_Macrome_offensive_tool_keyword = /Macrome\s.{0,100}\-\-payload/ nocase ascii wide
                        $string15_Macrome_offensive_tool_keyword = "Macrome build" nocase ascii wide
                        $string16_Macrome_offensive_tool_keyword = /Macrome\.csproj/ nocase ascii wide
                        $string17_Macrome_offensive_tool_keyword = /Macrome\.dll/ nocase ascii wide
                        $string18_Macrome_offensive_tool_keyword = /Macrome\.sln/ nocase ascii wide
                        $string19_Macrome_offensive_tool_keyword = /\-\-path\sdocToDump\.xls/ nocase ascii wide
                        $string20_Macrome_offensive_tool_keyword = "--payload-type Macro" nocase ascii wide
                        $string21_Macrome_offensive_tool_keyword = /ReadyToPhish\.xls/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}