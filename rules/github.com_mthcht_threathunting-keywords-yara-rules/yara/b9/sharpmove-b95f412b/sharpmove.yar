rule SharpMove
{
    meta:
        description = "Detection patterns for the tool 'SharpMove' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMove"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\saction\=dcom\scomputername\=.{0,100}\scommand\=.{0,100}\sthrow\=wmi\s/ nocase ascii wide
                        $string2 = /\/SharpMove\.exe/ nocase ascii wide
                        $string3 = /\/SharpMove\.exe/ nocase ascii wide
                        $string4 = /\/SharpMove\.git/ nocase ascii wide
                        $string5 = /\\SharpMove\.exe/ nocase ascii wide
                        $string6 = /\\SharpMove\.exe/ nocase ascii wide
                        $string7 = /\\SharpMove\.sln/ nocase ascii wide
                        $string8 = "0xthirteen/SharpMove" nocase ascii wide
                        $string9 = "4592e0848e4929ac2b6ba4593f8cbfe09f52ce6ca4206ce52087a31073903645" nocase ascii wide
                        $string10 = "6093461c4db41a15fefc85a28e35a9e359d0e9452bbfd36ce1fbe7aa31e1f4f0" nocase ascii wide
                        $string11 = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
                        $string12 = "'Product'>SharpMove" nocase ascii wide
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