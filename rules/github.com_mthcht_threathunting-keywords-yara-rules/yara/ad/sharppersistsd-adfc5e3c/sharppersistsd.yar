rule SharpPersistSD
{
    meta:
        description = "Detection patterns for the tool 'SharpPersistSD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPersistSD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSharpPersistSD\.dll/ nocase ascii wide
                        $string2 = /\/SharpPersistSD\.dll/ nocase ascii wide
                        $string3 = /\/SharpPersistSD\.git/ nocase ascii wide
                        $string4 = /\[\+\]\sUsing\sWMI\sto\sset\sWMI\sSD/ nocase ascii wide
                        $string5 = /\\SharpPersistSD\.cs/ nocase ascii wide
                        $string6 = /\\SharpPersistSD\.dll/ nocase ascii wide
                        $string7 = /\\SharpPersistSD\.sln/ nocase ascii wide
                        $string8 = "107EBC1B-0273-4B3D-B676-DE64B7F52B33" nocase ascii wide
                        $string9 = "1db1f717560d1c53a8ec668a80aad419da22a84b1705f7dfbcc3075634634f64" nocase ascii wide
                        $string10 = "cybersectroll/SharpPersistSD" nocase ascii wide
                        $string11 = "e3e2ced2569d1ebef8f65b554979747881e5e060355fa6698c913036dfd892ba" nocase ascii wide
                        $string12 = "f44bdc821e6588197e6d1b868a60aa140f20971a6eaeeb9e2a52bdb4065b7fd7" nocase ascii wide
                        $string13 = "f93389056fa9ad53e214a468aa495adcb2ff1b75a64cd7df77a63a173066d05a" nocase ascii wide
                        $string14 = "net localgroup administrators /add troll" nocase ascii wide
                        $string15 = "net users /add troll Trolololol123" nocase ascii wide
                        $string16 = /SharpPersistSD\.RegHelper/ nocase ascii wide
                        $string17 = /SharpPersistSD\.SecurityDescriptor/ nocase ascii wide
                        $string18 = /SharpPersistSD\.SvcHelper/ nocase ascii wide
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