rule rule_GhostDriver_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GhostDriver' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostDriver"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GhostDriver_offensive_tool_keyword = /\sGhostDriver\.exe/ nocase ascii wide
                        $string2_GhostDriver_offensive_tool_keyword = /\sghostdriver\.sys/ nocase ascii wide
                        $string3_GhostDriver_offensive_tool_keyword = /\/GhostDriver\.exe/ nocase ascii wide
                        $string4_GhostDriver_offensive_tool_keyword = /\/GhostDriver\.git/ nocase ascii wide
                        $string5_GhostDriver_offensive_tool_keyword = /\/ghostdriver\.sys/ nocase ascii wide
                        $string6_GhostDriver_offensive_tool_keyword = /\[\!\]\scleaning\sup\sall\sIOCs\sfiles\sto\savoid\sdetection\!/ nocase ascii wide
                        $string7_GhostDriver_offensive_tool_keyword = /\\GhostDriver\.exe/ nocase ascii wide
                        $string8_GhostDriver_offensive_tool_keyword = /\\ghostdriver\.sys/ nocase ascii wide
                        $string9_GhostDriver_offensive_tool_keyword = /\\GhostDriver\-main\\/ nocase ascii wide
                        $string10_GhostDriver_offensive_tool_keyword = /\\rentdrv\.log/ nocase ascii wide
                        $string11_GhostDriver_offensive_tool_keyword = "BlackSnufkin/GhostDriver" nocase ascii wide
                        $string12_GhostDriver_offensive_tool_keyword = /GhostDriver\.exe\s/ nocase ascii wide
                        $string13_GhostDriver_offensive_tool_keyword = /GhostDriver\-main\.zip/ nocase ascii wide

    condition:
        any of them
}