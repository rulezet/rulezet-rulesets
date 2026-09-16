rule RasmanPotato
{
    meta:
        description = "Detection patterns for the tool 'RasmanPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RasmanPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\srasman\.exe/ nocase ascii wide
                        $string2 = /\/rasman\.exe/ nocase ascii wide
                        $string3 = "/RasmanPotato" nocase ascii wide
                        $string4 = /\[\!\]\sRasman\sservice\sis\snot\srunning\!/ nocase ascii wide
                        $string5 = /\[\+\]\sRasman\sservice\sis\serror/ nocase ascii wide
                        $string6 = /\[\+\]\sRasman\sservice\sis\srunning\!/ nocase ascii wide
                        $string7 = /\\RasMan\.cpp/ nocase ascii wide
                        $string8 = /\\rasman\.exe/ nocase ascii wide
                        $string9 = /\\RasMan\.sln/ nocase ascii wide
                        $string10 = /\\RasmanPotato/ nocase ascii wide
                        $string11 = "5AC309CE-1223-4FF5-AF84-24BCD0B9E4DC" nocase ascii wide
                        $string12 = /anypotato\.exe/ nocase ascii wide
                        $string13 = /Choose\sThe\sRPC\sFunction\s\[1\]VpnProtEngWinRtConnect\s\[2\]VpnProtEngGetInterface/ nocase ascii wide
                        $string14 = "dae7d1a42b0bb178bff2ca9729c31d59db045cd65db817cc9eca7a1721bc4c57" nocase ascii wide
                        $string15 = "magicRasMan" nocase ascii wide
                        $string16 = "Provided that the current user has the SeImpersonate privilege, this tool will have an escalation to SYSTEM" nocase ascii wide
                        $string17 = /rasman.{0,100}whoami/ nocase ascii wide
                        $string18 = /RasMan\.vcxproj/ nocase ascii wide
                        $string19 = /rasman_c\.c/ nocase ascii wide
                        $string20 = /rasman_h\.h/ nocase ascii wide
                        $string21 = "RasmanPotato-master" nocase ascii wide
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