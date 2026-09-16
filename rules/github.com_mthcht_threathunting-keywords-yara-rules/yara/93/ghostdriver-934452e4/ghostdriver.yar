rule GhostDriver
{
    meta:
        description = "Detection patterns for the tool 'GhostDriver' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostDriver"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGhostDriver\.exe/ nocase ascii wide
                        $string2 = /\sghostdriver\.sys/ nocase ascii wide
                        $string3 = /\/GhostDriver\.exe/ nocase ascii wide
                        $string4 = /\/GhostDriver\.git/ nocase ascii wide
                        $string5 = /\/ghostdriver\.sys/ nocase ascii wide
                        $string6 = /\[\!\]\scleaning\sup\sall\sIOCs\sfiles\sto\savoid\sdetection\!/ nocase ascii wide
                        $string7 = /\\GhostDriver\.exe/ nocase ascii wide
                        $string8 = /\\ghostdriver\.sys/ nocase ascii wide
                        $string9 = /\\GhostDriver\-main\\/ nocase ascii wide
                        $string10 = /\\rentdrv\.log/ nocase ascii wide
                        $string11 = "BlackSnufkin/GhostDriver" nocase ascii wide
                        $string12 = /GhostDriver\.exe\s/ nocase ascii wide
                        $string13 = /GhostDriver\-main\.zip/ nocase ascii wide

    condition:
        any of them
}