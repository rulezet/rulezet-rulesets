rule fgdump
{
    meta:
        description = "Detection patterns for the tool 'fgdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fgdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/fgdump\.git/ nocase ascii wide
                        $string2 = /\\killmsas\.exe/ nocase ascii wide
                        $string3 = /\\pipe\\\\cachedumppipe/ nocase ascii wide
                        $string4 = /\\pipe\\cachedumppipe/ nocase ascii wide
                        $string5 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301" nocase ascii wide
                        $string6 = "1526febbe627085a24dd59eefa206fddd88326d78beb00b6630989cc13526733" nocase ascii wide
                        $string7 = "7A87DEAE-7B94-4986-9294-BD69B12A9732" nocase ascii wide
                        $string8 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46" nocase ascii wide
                        $string9 = "a96e22322b009000a8b0b8cf7229f4e40c36b260f1076f1c225c12a43613c405" nocase ascii wide
                        $string10 = "CacheDump service successfully installed" nocase ascii wide
                        $string11 = /cachedump\.exe/ nocase ascii wide
                        $string12 = /cachedump64\.exe/ nocase ascii wide
                        $string13 = "CD8FD3D4-15FD-489C-A334-91F551B98022" nocase ascii wide
                        $string14 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e" nocase ascii wide
                        $string15 = "E1D50AB4-E1CD-4C31-AED5-E957D2E6B01F" nocase ascii wide
                        $string16 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5" nocase ascii wide
                        $string17 = /fgdump\.exe/ nocase ascii wide
                        $string18 = "fgexec -c " nocase ascii wide
                        $string19 = /fgexec\.exe/ nocase ascii wide
                        $string20 = "ihamburglar/fgdump" nocase ascii wide
                        $string21 = /Kill\sCacheDump\sservice\s\(shouldn\'t\sbe\sused\)/ nocase ascii wide
                        $string22 = /pstgdump\.exe/ nocase ascii wide
                        $string23 = /pwdump\.exe/ nocase ascii wide
                        $string24 = "pwdump/cachedump" nocase ascii wide
                        $string25 = /servpw\.exe/ nocase ascii wide
                        $string26 = /servpw64\.exe/ nocase ascii wide

    condition:
        any of them
}