rule rule_RustPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RustPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RustPotato_offensive_tool_keyword = " -p 4444 -c powershell" nocase ascii wide
                        $string2_RustPotato_offensive_tool_keyword = "/pipe/RustPotato" nocase ascii wide
                        $string3_RustPotato_offensive_tool_keyword = /\/RustPotato\.git/ nocase ascii wide
                        $string4_RustPotato_offensive_tool_keyword = /\[\-\]\sFailed\sto\sstart\sreverse\sshell/ nocase ascii wide
                        $string5_RustPotato_offensive_tool_keyword = /\\\\pipe\\\\RustPotato/ nocase ascii wide
                        $string6_RustPotato_offensive_tool_keyword = /\\pipe\\RustPotato/ nocase ascii wide
                        $string7_RustPotato_offensive_tool_keyword = /\\RustPotato\-main/ nocase ascii wide
                        $string8_RustPotato_offensive_tool_keyword = "emdnaia/RustPotato" nocase ascii wide
                        $string9_RustPotato_offensive_tool_keyword = "f458f32e49cf7c57bd3bd32e9c82217f2faab412155c9e2a7c28d1b1b4848c42" nocase ascii wide
                        $string10_RustPotato_offensive_tool_keyword = "localhost/pipe/RustPotato" nocase ascii wide
                        $string11_RustPotato_offensive_tool_keyword = /RustPotato\.exe/ nocase ascii wide

    condition:
        any of them
}