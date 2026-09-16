rule winexe
{
    meta:
        description = "Detection patterns for the tool 'winexe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winexe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/kalilinux/packages/winexe"
                        $string2 = /\/winexe\s.{0,1000}\-\-runas/
                        $string3 = "/winexe -U "
                        $string4 = /\/winexe\.git/
                        $string5 = /\/winexe\-0\.91\.tar\.gz/
                        $string6 = /\/winexe\-1\.00\.tar\.gz/
                        $string7 = /\\winexesvc\.exe/ nocase ascii wide
                        $string8 = ">winexesvc<" nocase ascii wide
                        $string9 = "2077c0c96383793ffa5b0843740f9b095688df5f5accd1a74c65f634bbc42358"
                        $string10 = "60f25c8a290ba6185b07da48663cfc4662e2853e324bef2a272aede4c15260d2"
                        $string11 = "99238bd3e1c0637041c737c86a05bd73a9375abc9794dca71d2765e22d87537e"
                        $string12 = "apt install winexe"
                        $string13 = /https\:\/\/sourceforge\.net\/projects\/winexe/
                        $string14 = "skalkoto/winexe"
                        $string15 = /winexesvc32\.exe/
                        $string16 = /winexesvc64\.exe/

    condition:
        any of them
}