rule rule_winexe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'winexe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winexe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_winexe_offensive_tool_keyword = "/kalilinux/packages/winexe"
                        $string2_winexe_offensive_tool_keyword = /\/winexe\s.{0,1000}\-\-runas/
                        $string3_winexe_offensive_tool_keyword = "/winexe -U "
                        $string4_winexe_offensive_tool_keyword = /\/winexe\.git/
                        $string5_winexe_offensive_tool_keyword = /\/winexe\-0\.91\.tar\.gz/
                        $string6_winexe_offensive_tool_keyword = /\/winexe\-1\.00\.tar\.gz/
                        $string7_winexe_offensive_tool_keyword = /\\winexesvc\.exe/ nocase ascii wide
                        $string8_winexe_offensive_tool_keyword = ">winexesvc<" nocase ascii wide
                        $string9_winexe_offensive_tool_keyword = "2077c0c96383793ffa5b0843740f9b095688df5f5accd1a74c65f634bbc42358"
                        $string10_winexe_offensive_tool_keyword = "60f25c8a290ba6185b07da48663cfc4662e2853e324bef2a272aede4c15260d2"
                        $string11_winexe_offensive_tool_keyword = "99238bd3e1c0637041c737c86a05bd73a9375abc9794dca71d2765e22d87537e"
                        $string12_winexe_offensive_tool_keyword = "apt install winexe"
                        $string13_winexe_offensive_tool_keyword = /https\:\/\/sourceforge\.net\/projects\/winexe/
                        $string14_winexe_offensive_tool_keyword = "skalkoto/winexe"
                        $string15_winexe_offensive_tool_keyword = /winexesvc32\.exe/
                        $string16_winexe_offensive_tool_keyword = /winexesvc64\.exe/

    condition:
        any of them
}