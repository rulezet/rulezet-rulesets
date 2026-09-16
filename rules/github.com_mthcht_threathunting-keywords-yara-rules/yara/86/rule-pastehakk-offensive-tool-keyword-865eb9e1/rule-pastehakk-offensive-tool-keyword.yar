rule rule_pastehakk_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pastehakk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastehakk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pastehakk_offensive_tool_keyword = /\spastehakk\.sh/
                        $string2_pastehakk_offensive_tool_keyword = /\$\{White\}A\stool\sto\sperform\sclipboard\spoisoning\sattack/
                        $string3_pastehakk_offensive_tool_keyword = /\$Green\sInfecting\shtml\sfile/
                        $string4_pastehakk_offensive_tool_keyword = /\/pastehakk\.git/ nocase ascii wide
                        $string5_pastehakk_offensive_tool_keyword = /\/pastehakk\.sh/
                        $string6_pastehakk_offensive_tool_keyword = "3xploitGuy/pastehakk" nocase ascii wide
                        $string7_pastehakk_offensive_tool_keyword = "53a9c6eed3ee5ed0ea6fe900bbcdac2b9c0709c57c8d82688ef32f7e2b784f60"
                        $string8_pastehakk_offensive_tool_keyword = "clear; history -c"
                        $string9_pastehakk_offensive_tool_keyword = "pastehakk_generate"
                        $string10_pastehakk_offensive_tool_keyword = /sandeshyadavm46\@gmail\.com/

    condition:
        any of them
}