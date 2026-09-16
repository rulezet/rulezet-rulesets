rule EDRPrison
{
    meta:
        description = "Detection patterns for the tool 'EDRPrison' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRPrison"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EDRPrison\.git/ nocase ascii wide
                        $string2 = /\\EDRPrison\.csproj/ nocase ascii wide
                        $string3 = /\\EDRPrison\-main/ nocase ascii wide
                        $string4 = "036fedcd8c1d30e41ad0f36aa87f90338b7d1310632c729706d918a34d398eb5" nocase ascii wide
                        $string5 = "1cbb36d4cf2b775b3009d1d33ce8a90c8a321cc30b884250639142cea085ac06" nocase ascii wide
                        $string6 = "9674DF71-0814-4398-8A77-5A32A8CBE61E" nocase ascii wide
                        $string7 = "senzee1984/EDRPrison" nocase ascii wide
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