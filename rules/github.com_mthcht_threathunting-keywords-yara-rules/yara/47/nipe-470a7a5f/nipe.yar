rule nipe
{
    meta:
        description = "Detection patterns for the tool 'nipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/etc\/init\.d\/tor\sstart/
                        $string2 = /\/etc\/init\.d\/tor\sstop/
                        $string3 = /\/nipe\.git/ nocase ascii wide
                        $string4 = /\/nipe\.pl/ nocase ascii wide
                        $string5 = "/var/run/tor/control"
                        $string6 = /\/var\/run\/tor\/tor\.pid/
                        $string7 = "htrgouvea/nipe" nocase ascii wide
                        $string8 = "htrgouvea/nipe" nocase ascii wide
                        $string9 = /nipe\.pl\s/ nocase ascii wide
                        $string10 = /perl\snipe\.pl\sinstall/ nocase ascii wide
                        $string11 = /perl\snipe\.pl\sstart/ nocase ascii wide
                        $string12 = "systemctl start tor" nocase ascii wide
                        $string13 = /tor\s\-f\s\.configs\/.{0,100}\-torrc/ nocase ascii wide
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