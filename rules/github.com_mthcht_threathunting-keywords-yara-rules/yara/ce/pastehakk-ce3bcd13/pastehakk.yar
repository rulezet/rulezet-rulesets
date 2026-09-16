rule pastehakk
{
    meta:
        description = "Detection patterns for the tool 'pastehakk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastehakk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spastehakk\.sh/
                        $string2 = /\$\{White\}A\stool\sto\sperform\sclipboard\spoisoning\sattack/
                        $string3 = /\$Green\sInfecting\shtml\sfile/
                        $string4 = /\/pastehakk\.git/ nocase ascii wide
                        $string5 = /\/pastehakk\.sh/
                        $string6 = "3xploitGuy/pastehakk" nocase ascii wide
                        $string7 = "53a9c6eed3ee5ed0ea6fe900bbcdac2b9c0709c57c8d82688ef32f7e2b784f60"
                        $string8 = "clear; history -c"
                        $string9 = "pastehakk_generate"
                        $string10 = /sandeshyadavm46\@gmail\.com/

    condition:
        any of them
}