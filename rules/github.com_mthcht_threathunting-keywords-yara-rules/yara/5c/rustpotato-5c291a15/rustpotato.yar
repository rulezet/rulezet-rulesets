rule RustPotato
{
    meta:
        description = "Detection patterns for the tool 'RustPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -p 4444 -c powershell" nocase ascii wide
                        $string2 = "/pipe/RustPotato" nocase ascii wide
                        $string3 = /\/RustPotato\.git/ nocase ascii wide
                        $string4 = /\[\-\]\sFailed\sto\sstart\sreverse\sshell/ nocase ascii wide
                        $string5 = /\\\\pipe\\\\RustPotato/ nocase ascii wide
                        $string6 = /\\pipe\\RustPotato/ nocase ascii wide
                        $string7 = /\\RustPotato\-main/ nocase ascii wide
                        $string8 = "emdnaia/RustPotato" nocase ascii wide
                        $string9 = "f458f32e49cf7c57bd3bd32e9c82217f2faab412155c9e2a7c28d1b1b4848c42" nocase ascii wide
                        $string10 = "localhost/pipe/RustPotato" nocase ascii wide
                        $string11 = /RustPotato\.exe/ nocase ascii wide

    condition:
        any of them
}