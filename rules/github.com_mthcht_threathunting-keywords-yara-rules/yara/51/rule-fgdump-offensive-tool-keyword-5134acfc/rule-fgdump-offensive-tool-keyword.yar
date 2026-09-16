rule rule_fgdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fgdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fgdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fgdump_offensive_tool_keyword = /\/fgdump\.git/ nocase ascii wide
                        $string2_fgdump_offensive_tool_keyword = /\\killmsas\.exe/ nocase ascii wide
                        $string3_fgdump_offensive_tool_keyword = /\\pipe\\\\cachedumppipe/ nocase ascii wide
                        $string4_fgdump_offensive_tool_keyword = /\\pipe\\cachedumppipe/ nocase ascii wide
                        $string5_fgdump_offensive_tool_keyword = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301" nocase ascii wide
                        $string6_fgdump_offensive_tool_keyword = "1526febbe627085a24dd59eefa206fddd88326d78beb00b6630989cc13526733" nocase ascii wide
                        $string7_fgdump_offensive_tool_keyword = "7A87DEAE-7B94-4986-9294-BD69B12A9732" nocase ascii wide
                        $string8_fgdump_offensive_tool_keyword = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46" nocase ascii wide
                        $string9_fgdump_offensive_tool_keyword = "a96e22322b009000a8b0b8cf7229f4e40c36b260f1076f1c225c12a43613c405" nocase ascii wide
                        $string10_fgdump_offensive_tool_keyword = "CacheDump service successfully installed" nocase ascii wide
                        $string11_fgdump_offensive_tool_keyword = /cachedump\.exe/ nocase ascii wide
                        $string12_fgdump_offensive_tool_keyword = /cachedump64\.exe/ nocase ascii wide
                        $string13_fgdump_offensive_tool_keyword = "CD8FD3D4-15FD-489C-A334-91F551B98022" nocase ascii wide
                        $string14_fgdump_offensive_tool_keyword = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e" nocase ascii wide
                        $string15_fgdump_offensive_tool_keyword = "E1D50AB4-E1CD-4C31-AED5-E957D2E6B01F" nocase ascii wide
                        $string16_fgdump_offensive_tool_keyword = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5" nocase ascii wide
                        $string17_fgdump_offensive_tool_keyword = /fgdump\.exe/ nocase ascii wide
                        $string18_fgdump_offensive_tool_keyword = "fgexec -c " nocase ascii wide
                        $string19_fgdump_offensive_tool_keyword = /fgexec\.exe/ nocase ascii wide
                        $string20_fgdump_offensive_tool_keyword = "ihamburglar/fgdump" nocase ascii wide
                        $string21_fgdump_offensive_tool_keyword = /Kill\sCacheDump\sservice\s\(shouldn\'t\sbe\sused\)/ nocase ascii wide
                        $string22_fgdump_offensive_tool_keyword = /pstgdump\.exe/ nocase ascii wide
                        $string23_fgdump_offensive_tool_keyword = /pwdump\.exe/ nocase ascii wide
                        $string24_fgdump_offensive_tool_keyword = "pwdump/cachedump" nocase ascii wide
                        $string25_fgdump_offensive_tool_keyword = /servpw\.exe/ nocase ascii wide
                        $string26_fgdump_offensive_tool_keyword = /servpw64\.exe/ nocase ascii wide

    condition:
        any of them
}