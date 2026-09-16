rule Invisi_Shell
{
    meta:
        description = "Detection patterns for the tool 'Invisi-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invisi-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Invisi\-Shell\.git/ nocase ascii wide
                        $string2 = /\\RunWithPathAsAdmin\.bat/ nocase ascii wide
                        $string3 = /\\RunWithRegistryNonAdmin\.bat/ nocase ascii wide
                        $string4 = "18A66118-B98D-4FFC-AABE-DAFF5779F14C" nocase ascii wide
                        $string5 = "4a8e184ca9e1ccc775b224a48d344ce13dde26a86a634df2853ce7a27c17765c" nocase ascii wide
                        $string6 = "833d68452ea956b5d23bcb243cd327bd05dfd79fb5a4a34064783749eafa1ddf" nocase ascii wide
                        $string7 = "835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e" nocase ascii wide
                        $string8 = "835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e" nocase ascii wide
                        $string9 = "Invisi-Shell" nocase ascii wide
                        $string10 = /InvisiShellProfiler\.cpp/ nocase ascii wide
                        $string11 = /InvisiShellProfiler\.def/ nocase ascii wide
                        $string12 = /InvisiShellProfiler\.dll/ nocase ascii wide
                        $string13 = /InvisiShellProfiler\.h/ nocase ascii wide
                        $string14 = /InvisiShellProfiler\.pdb/ nocase ascii wide
                        $string15 = /InvisiShellProfiler\.vcxproj/ nocase ascii wide
                        $string16 = "OmerYa/Invisi-Shell" nocase ascii wide

    condition:
        any of them
}