rule Volumiser
{
    meta:
        description = "Detection patterns for the tool 'Volumiser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Volumiser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sVolumiser\.exe\s/ nocase ascii wide
                        $string2 = "/CCob/Volumiser" nocase ascii wide
                        $string3 = /\/Volumiser\.exe/ nocase ascii wide
                        $string4 = /\/Volumiser\.git/ nocase ascii wide
                        $string5 = /\/Volumiser\-maser\.zip/ nocase ascii wide
                        $string6 = /\\Volumiser\.exe/ nocase ascii wide
                        $string7 = /\\Volumiser\.sln/ nocase ascii wide
                        $string8 = /\\Volumiser\\Program\.cs/ nocase ascii wide
                        $string9 = "0DF38AD4-60AF-4F93-9C7A-7FB7BA692017" nocase ascii wide
                        $string10 = /Volumiser\.exe\s\-\-image/ nocase ascii wide
                        $string11 = /Volumiser\\DiscUtils\.Ebs\\EbsMappedStream/ nocase ascii wide
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