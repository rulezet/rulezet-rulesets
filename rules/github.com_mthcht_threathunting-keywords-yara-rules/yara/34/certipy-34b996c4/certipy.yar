rule Certipy
{
    meta:
        description = "Detection patterns for the tool 'Certipy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certipy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " certipy-ad" nocase ascii wide
                        $string2 = /\s\-dns\-tcp\s\-nameserver\s.{0,100}\s\-dc\-ip/ nocase ascii wide
                        $string3 = " -no-pass -dns-tcp -nameserver" nocase ascii wide
                        $string4 = " -old-bloodhound" nocase ascii wide
                        $string5 = /\sshadow\sauto\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-account\s/ nocase ascii wide
                        $string6 = /\.exe\sfind\s\-username\s.{0,100}\s\-dc\-ip\s/ nocase ascii wide
                        $string7 = /\/Certipy\.git/ nocase ascii wide
                        $string8 = "/Certipy/" nocase ascii wide
                        $string9 = /\/certipy64\.exe/ nocase ascii wide
                        $string10 = /\\certipy64\.exe/ nocase ascii wide
                        $string11 = "certipy account " nocase ascii wide
                        $string12 = "certipy auth " nocase ascii wide
                        $string13 = "certipy ca " nocase ascii wide
                        $string14 = "certipy ca -backup" nocase ascii wide
                        $string15 = "certipy cert " nocase ascii wide
                        $string16 = "certipy find " nocase ascii wide
                        $string17 = "certipy forge " nocase ascii wide
                        $string18 = "certipy forge " nocase ascii wide
                        $string19 = "certipy relay " nocase ascii wide
                        $string20 = "certipy req " nocase ascii wide
                        $string21 = "certipy shadow " nocase ascii wide
                        $string22 = "certipy template " nocase ascii wide
                        $string23 = /certipy\-master\.zip/ nocase ascii wide
                        $string24 = "ly4k/Certipy" nocase ascii wide
                        $string25 = "certipy " nocase ascii wide
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