rule Lockless
{
    meta:
        description = "Detection patterns for the tool 'Lockless' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lockless"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/LockLess\.exe/ nocase ascii wide
                        $string2 = /\/Lockless\.git/ nocase ascii wide
                        $string3 = /\\LockLess\.csproj/ nocase ascii wide
                        $string4 = /\\LockLess\.exe/ nocase ascii wide
                        $string5 = /\\LockLess\.sln/ nocase ascii wide
                        $string6 = "8c90af89b3f0c90d39396210b6dc8dc19ff9e5ce183463a01affa6d30c5d7414" nocase ascii wide
                        $string7 = "A91421CB-7909-4383-BA43-C2992BBBAC22" nocase ascii wide
                        $string8 = "c591ed58f48171fa285464339a17acd1c267c0299df9f0b4e53eed9a8acb8f9f" nocase ascii wide
                        $string9 = "f05885a68c1f16c7cbaa3657bbc57f54b7755910d1c96366543cc428729abcb3" nocase ascii wide
                        $string10 = "GhostPack/Lockless" nocase ascii wide
                        $string11 = /LockLess\.exe\s.{0,100}\/copy/ nocase ascii wide
                        $string12 = /LockLess\.exe\sall/ nocase ascii wide
                        $string13 = "namespace LockLess" nocase ascii wide
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