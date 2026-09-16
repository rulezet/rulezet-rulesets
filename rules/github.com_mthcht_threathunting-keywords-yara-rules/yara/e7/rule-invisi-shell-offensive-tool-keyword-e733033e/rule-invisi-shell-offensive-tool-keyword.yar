rule rule_Invisi_Shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invisi-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invisi-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invisi_Shell_offensive_tool_keyword = /\/Invisi\-Shell\.git/ nocase ascii wide
                        $string2_Invisi_Shell_offensive_tool_keyword = /\\RunWithPathAsAdmin\.bat/ nocase ascii wide
                        $string3_Invisi_Shell_offensive_tool_keyword = /\\RunWithRegistryNonAdmin\.bat/ nocase ascii wide
                        $string4_Invisi_Shell_offensive_tool_keyword = "18A66118-B98D-4FFC-AABE-DAFF5779F14C" nocase ascii wide
                        $string5_Invisi_Shell_offensive_tool_keyword = "4a8e184ca9e1ccc775b224a48d344ce13dde26a86a634df2853ce7a27c17765c" nocase ascii wide
                        $string6_Invisi_Shell_offensive_tool_keyword = "833d68452ea956b5d23bcb243cd327bd05dfd79fb5a4a34064783749eafa1ddf" nocase ascii wide
                        $string7_Invisi_Shell_offensive_tool_keyword = "835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e" nocase ascii wide
                        $string8_Invisi_Shell_offensive_tool_keyword = "835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e" nocase ascii wide
                        $string9_Invisi_Shell_offensive_tool_keyword = "Invisi-Shell" nocase ascii wide
                        $string10_Invisi_Shell_offensive_tool_keyword = /InvisiShellProfiler\.cpp/ nocase ascii wide
                        $string11_Invisi_Shell_offensive_tool_keyword = /InvisiShellProfiler\.def/ nocase ascii wide
                        $string12_Invisi_Shell_offensive_tool_keyword = /InvisiShellProfiler\.dll/ nocase ascii wide
                        $string13_Invisi_Shell_offensive_tool_keyword = /InvisiShellProfiler\.h/ nocase ascii wide
                        $string14_Invisi_Shell_offensive_tool_keyword = /InvisiShellProfiler\.pdb/ nocase ascii wide
                        $string15_Invisi_Shell_offensive_tool_keyword = /InvisiShellProfiler\.vcxproj/ nocase ascii wide
                        $string16_Invisi_Shell_offensive_tool_keyword = "OmerYa/Invisi-Shell" nocase ascii wide

    condition:
        any of them
}