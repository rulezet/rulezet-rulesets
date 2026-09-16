rule SharpRDP
{
    meta:
        description = "Detection patterns for the tool 'SharpRDP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Execute command elevated through Run Dialog" nocase ascii wide
                        $string2 = " Execute command elevated through task manager" nocase ascii wide
                        $string3 = /\.exe\scomputername\=.{0,100}\scommand\=.{0,100}\susername\=.{0,100}\spassword\=.{0,100}\snla\=true/ nocase ascii wide
                        $string4 = /\.exe\scomputername\=.{0,100}\scommand\=.{0,100}\susername\=.{0,100}\spassword\=.{0,100}\stakeover\=true/ nocase ascii wide
                        $string5 = /\.exe\scomputername\=.{0,100}\scommand\=.{0,100}\susername\=.{0,100}\spassword\=.{0,100}\sconnectdrive\=true/ nocase ascii wide
                        $string6 = /\.exe\scomputername\=.{0,100}\scommand\=.{0,100}\susername\=.{0,100}\spassword\=.{0,100}\selevated\=taskmgr/ nocase ascii wide
                        $string7 = /\.exe\scomputername\=.{0,100}\scommand\=.{0,100}\susername\=.{0,100}\spassword\=.{0,100}\selevated\=winr/ nocase ascii wide
                        $string8 = /\.exe\scomputername\=.{0,100}\scommand\=.{0,100}\susername\=.{0,100}\spassword\=.{0,100}\sexec\=cmd/ nocase ascii wide
                        $string9 = /\.WriteLine\(\\"SharpRDP\\"\)/ nocase ascii wide
                        $string10 = /\/SharpRDP\.exe/ nocase ascii wide
                        $string11 = /\/SharpRDP\.git/ nocase ascii wide
                        $string12 = /\\SharpRDP\.exe/ nocase ascii wide
                        $string13 = /\\SharpRDP\.pdb/ nocase ascii wide
                        $string14 = /\\SharpRDP\\/ nocase ascii wide
                        $string15 = ">SharpRDP<" nocase ascii wide
                        $string16 = "0xthirteen/SharpRDP" nocase ascii wide
                        $string17 = /Ask\sto\stake\sover\sRDP\ssession\sif\sanother\sused\sis\slogged\sin\s\(workstation\)/ nocase ascii wide
                        $string18 = "b4726b5d0aa21ed0f06326fcf2f9bd0c6171c76b610287a357710174f06dea52" nocase ascii wide
                        $string19 = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" nocase ascii wide
                        $string20 = /SharpRDP\..{0,100}\.dll\.bin/ nocase ascii wide
                        $string21 = /SharpRDP\.csproj/ nocase ascii wide
                        $string22 = /SharpRDP\.exe/ nocase ascii wide
                        $string23 = /SharpRDP\.sln/ nocase ascii wide
                        $string24 = "SharpRDP-master" nocase ascii wide
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