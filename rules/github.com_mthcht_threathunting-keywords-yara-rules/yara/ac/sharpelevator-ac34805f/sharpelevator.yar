rule SharpElevator
{
    meta:
        description = "Detection patterns for the tool 'SharpElevator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpElevator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSharpElevator\.exe/ nocase ascii wide
                        $string2 = /\/SharpElevator\.exe/ nocase ascii wide
                        $string3 = /\/SharpElevator\.git/ nocase ascii wide
                        $string4 = /\[\+\]\sWOOT\!\sCreated\selevated\sprocess\s/ nocase ascii wide
                        $string5 = /\\SharpElevator\.cs/ nocase ascii wide
                        $string6 = /\\SharpElevator\.exe/ nocase ascii wide
                        $string7 = /\\SharpElevator\.sln/ nocase ascii wide
                        $string8 = "378f6e87219651f96e607e40c229e5f17df4ad71836409881fe3cc77c6780ac7" nocase ascii wide
                        $string9 = "42BDEFC0-0BAE-43DF-97BB-C805ABFBD078" nocase ascii wide
                        $string10 = "6a31601415f4b02531aa031b1f246cec9f652f62927bc9b3c4443aac9c2ff625" nocase ascii wide
                        $string11 = "a36ffb4f22598b5e983ef16251df49deb94ad0c41a8a1768503efe4d7e16ea40" nocase ascii wide
                        $string12 = "a67edb34ce2c10bb5c170445344da4ad809932ff8e82e2b6c45a260d5a47a859" nocase ascii wide
                        $string13 = "eladshamir/SharpElevator" nocase ascii wide
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