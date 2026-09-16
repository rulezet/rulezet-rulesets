rule rule_win_brute_logon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'win-brute-logon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "win-brute-logon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_win_brute_logon_offensive_tool_keyword = " darkcodersc " nocase ascii wide
                        $string2_win_brute_logon_offensive_tool_keyword = /\.exe\s\-v\s\-u\s.{0,100}\s\-w\s10k\-most\-common\.txt/ nocase ascii wide
                        $string3_win_brute_logon_offensive_tool_keyword = "/DarkCoderSc/" nocase ascii wide
                        $string4_win_brute_logon_offensive_tool_keyword = /\/Passwords\/Common\-Credentials\/10k\-most\-common\.txt/ nocase ascii wide
                        $string5_win_brute_logon_offensive_tool_keyword = "/WinBruteLogon" nocase ascii wide
                        $string6_win_brute_logon_offensive_tool_keyword = "/win-brute-logon" nocase ascii wide
                        $string7_win_brute_logon_offensive_tool_keyword = /\/win\-brute\-logon\.git/ nocase ascii wide
                        $string8_win_brute_logon_offensive_tool_keyword = "2FE6C1D0-0538-48DB-B4FA-55F0296A5150" nocase ascii wide
                        $string9_win_brute_logon_offensive_tool_keyword = "net localgroup administrators darkcodersc /add" nocase ascii wide
                        $string10_win_brute_logon_offensive_tool_keyword = "net localgroup guests GuestUser /add" nocase ascii wide
                        $string11_win_brute_logon_offensive_tool_keyword = "net localgroup users GuestUser /delete" nocase ascii wide
                        $string12_win_brute_logon_offensive_tool_keyword = "net user darkcodersc /add" nocase ascii wide
                        $string13_win_brute_logon_offensive_tool_keyword = "net user darkcodersc trousers" nocase ascii wide
                        $string14_win_brute_logon_offensive_tool_keyword = "net user GuestUser /add" nocase ascii wide
                        $string15_win_brute_logon_offensive_tool_keyword = "net user HackMe " nocase ascii wide
                        $string16_win_brute_logon_offensive_tool_keyword = "net user HackMe /add" nocase ascii wide
                        $string17_win_brute_logon_offensive_tool_keyword = "net user HackMe ozlq6qwm" nocase ascii wide
                        $string18_win_brute_logon_offensive_tool_keyword = "PhrozenIO/win-brute-logon" nocase ascii wide
                        $string19_win_brute_logon_offensive_tool_keyword = /WinBruteLogon.{0,100}\s\-v\s\-u/ nocase ascii wide
                        $string20_win_brute_logon_offensive_tool_keyword = /WinBruteLogon\.dpr/ nocase ascii wide
                        $string21_win_brute_logon_offensive_tool_keyword = /WinBruteLogon\.dproj/ nocase ascii wide
                        $string22_win_brute_logon_offensive_tool_keyword = /WinBruteLogon\.exe/ nocase ascii wide
                        $string23_win_brute_logon_offensive_tool_keyword = /WinBruteLogon\.exe/ nocase ascii wide
                        $string24_win_brute_logon_offensive_tool_keyword = /WinBruteLogon\.res/ nocase ascii wide
                        $string25_win_brute_logon_offensive_tool_keyword = /win\-brute\-logon\-master\.zip/ nocase ascii wide
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