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
                        $string2 = /\.exe\s\-v\s\-u\s.{0,1000}\s\-w\s10k\-most\-common\.txt/ nocase ascii wide
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
                        $string19 = /WinBruteLogon.{0,1000}\s\-v\s\-u/ nocase ascii wide
                        $string20 = /WinBruteLogon\.dpr/ nocase ascii wide
                        $string21 = /WinBruteLogon\.dproj/ nocase ascii wide
                        $string22 = /WinBruteLogon\.exe/ nocase ascii wide
                        $string23 = /WinBruteLogon\.exe/ nocase ascii wide
                        $string24 = /WinBruteLogon\.res/ nocase ascii wide
                        $string25 = /win\-brute\-logon\-master\.zip/ nocase ascii wide

    condition:
        any of them
}