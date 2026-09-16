rule fuegoshell
{
    meta:
        description = "Detection patterns for the tool 'fuegoshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuegoshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sgenerate_bind_fuegoshell\.ps1/ nocase ascii wide
                        $string2 = /\sgenerate_reverse_fuegoshell\.ps1/ nocase ascii wide
                        $string3 = /\$myC2ipAdress/ nocase ascii wide
                        $string4 = /\$myVictimIPAdress/ nocase ascii wide
                        $string5 = /\/fuegoshell\.git/ nocase ascii wide
                        $string6 = /\/generate_bind_fuegoshell\.ps1/ nocase ascii wide
                        $string7 = /\/generate_reverse_fuegoshell\.ps1/ nocase ascii wide
                        $string8 = /\[\+\]\sNew\sincoming\sshell\sfrom\s\:\s/ nocase ascii wide
                        $string9 = /\\generate_bind_fuegoshell\.ps1/ nocase ascii wide
                        $string10 = /\\generate_reverse_fuegoshell\.ps1/ nocase ascii wide
                        $string11 = /\>\\fuego\-control/ nocase ascii wide
                        $string12 = /\>\\fuego\-data/ nocase ascii wide
                        $string13 = /\>\\fuegoshell/ nocase ascii wide
                        $string14 = "5b64c12376f1ec1b876ede9b84f6883ee5f1ee5065e945dc2115c5e04c02aadf" nocase ascii wide
                        $string15 = "6c6c37d26619bfe90a84e3e70c8dd45073488e120d239500bef10977f8523073" nocase ascii wide
                        $string16 = "fuegoShell-bind>" nocase ascii wide
                        $string17 = "Fuegoshell-client started" nocase ascii wide
                        $string18 = "fuegoShell-reverse>" nocase ascii wide
                        $string19 = "Fuegoshell-server started" nocase ascii wide
                        $string20 = "Here are the oneliners for reverse shell using rpc named pipes" nocase ascii wide
                        $string21 = /v1k1ngfr\.github\.io\/fuegoshell\// nocase ascii wide
                        $string22 = "v1k1ngfr/fuegoshell" nocase ascii wide

    condition:
        any of them
}