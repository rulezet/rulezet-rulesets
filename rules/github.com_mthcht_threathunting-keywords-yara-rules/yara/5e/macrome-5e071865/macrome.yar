rule Macrome
{
    meta:
        description = "Detection patterns for the tool 'Macrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Macrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCharSubroutine\-Macro\.xls/ nocase ascii wide
                        $string2 = /\spopcalc\.bin\s/ nocase ascii wide
                        $string3 = /\spopcalc64\.bin\s/ nocase ascii wide
                        $string4 = /\/BaseNEncoder\.cs/ nocase ascii wide
                        $string5 = /\/BIFFRecordEncryption\.cs/ nocase ascii wide
                        $string6 = /\/ExcelDocWriter\.cs/ nocase ascii wide
                        $string7 = /\/MacroPatterns\.cs/ nocase ascii wide
                        $string8 = "/michaelweber/Macrome" nocase ascii wide
                        $string9 = /\/RC4BinaryEncryption\.cs/ nocase ascii wide
                        $string10 = /\/XorObfuscation\.cs/ nocase ascii wide
                        $string11 = /b2xtranslator\.xls\.csproj/ nocase ascii wide
                        $string12 = /decoy_document\.xls/ nocase ascii wide
                        $string13 = /Macrome\s.{0,100}\-\-decoy\-document/ nocase ascii wide
                        $string14 = /Macrome\s.{0,100}\-\-payload/ nocase ascii wide
                        $string15 = "Macrome build" nocase ascii wide
                        $string16 = /Macrome\.csproj/ nocase ascii wide
                        $string17 = /Macrome\.dll/ nocase ascii wide
                        $string18 = /Macrome\.sln/ nocase ascii wide
                        $string19 = /\-\-path\sdocToDump\.xls/ nocase ascii wide
                        $string20 = "--payload-type Macro" nocase ascii wide
                        $string21 = /ReadyToPhish\.xls/ nocase ascii wide
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