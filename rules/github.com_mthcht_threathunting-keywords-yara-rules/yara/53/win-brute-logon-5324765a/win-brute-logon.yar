rule win_brute_logon
{
    meta:
        description = "Detection patterns for the tool 'win-brute-logon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "win-brute-logon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " darkcodersc " nocase ascii wide
                        $string2 = /\.exe\s\-v\s\-u\s.{0,100}\s\-w\s10k\-most\-common\.txt/ nocase ascii wide
                        $string3 = "/DarkCoderSc/" nocase ascii wide
                        $string4 = /\/Passwords\/Common\-Credentials\/10k\-most\-common\.txt/ nocase ascii wide
                        $string5 = "/WinBruteLogon" nocase ascii wide
                        $string6 = "/win-brute-logon" nocase ascii wide
                        $string7 = /\/win\-brute\-logon\.git/ nocase ascii wide
                        $string8 = "2FE6C1D0-0538-48DB-B4FA-55F0296A5150" nocase ascii wide
                        $string9 = "net localgroup administrators darkcodersc /add" nocase ascii wide
                        $string10 = "net localgroup guests GuestUser /add" nocase ascii wide
                        $string11 = "net localgroup users GuestUser /delete" nocase ascii wide
                        $string12 = "net user darkcodersc /add" nocase ascii wide
                        $string13 = "net user darkcodersc trousers" nocase ascii wide
                        $string14 = "net user GuestUser /add" nocase ascii wide
                        $string15 = "net user HackMe " nocase ascii wide
                        $string16 = "net user HackMe /add" nocase ascii wide
                        $string17 = "net user HackMe ozlq6qwm" nocase ascii wide
                        $string18 = "PhrozenIO/win-brute-logon" nocase ascii wide
                        $string19 = /WinBruteLogon.{0,100}\s\-v\s\-u/ nocase ascii wide
                        $string20 = /WinBruteLogon\.dpr/ nocase ascii wide
                        $string21 = /WinBruteLogon\.dproj/ nocase ascii wide
                        $string22 = /WinBruteLogon\.exe/ nocase ascii wide
                        $string23 = /WinBruteLogon\.exe/ nocase ascii wide
                        $string24 = /WinBruteLogon\.res/ nocase ascii wide
                        $string25 = /win\-brute\-logon\-master\.zip/ nocase ascii wide
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