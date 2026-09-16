rule AutoSmuggle
{
    meta:
        description = "Detection patterns for the tool 'AutoSmuggle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSmuggle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AutoSmuggle\.git/ nocase ascii wide
                        $string2 = /\[.{0,100}\]\sSmuggling\sin\sHTML/ nocase ascii wide
                        $string3 = /\[.{0,100}\]\sSmuggling\sin\sSVG/ nocase ascii wide
                        $string4 = /\\AutoSmuggle\\.{0,100}\.cs/ nocase ascii wide
                        $string5 = "57A893C7-7527-4B55-B4E9-D644BBDA89D1" nocase ascii wide
                        $string6 = /AutoSmuggle\.csproj/ nocase ascii wide
                        $string7 = /AutoSmuggle\.exe/ nocase ascii wide
                        $string8 = /AutoSmuggle\.sln/ nocase ascii wide
                        $string9 = "AutoSmuggle-master" nocase ascii wide
                        $string10 = "surajpkhetani/AutoSmuggle" nocase ascii wide
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