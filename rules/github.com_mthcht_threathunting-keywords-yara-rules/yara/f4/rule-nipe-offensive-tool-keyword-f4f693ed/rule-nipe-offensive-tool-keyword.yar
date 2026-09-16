rule rule_nipe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nipe_offensive_tool_keyword = /\/etc\/init\.d\/tor\sstart/
                        $string2_nipe_offensive_tool_keyword = /\/etc\/init\.d\/tor\sstop/
                        $string3_nipe_offensive_tool_keyword = /\/nipe\.git/ nocase ascii wide
                        $string4_nipe_offensive_tool_keyword = /\/nipe\.pl/ nocase ascii wide
                        $string5_nipe_offensive_tool_keyword = "/var/run/tor/control"
                        $string6_nipe_offensive_tool_keyword = /\/var\/run\/tor\/tor\.pid/
                        $string7_nipe_offensive_tool_keyword = "htrgouvea/nipe" nocase ascii wide
                        $string8_nipe_offensive_tool_keyword = "htrgouvea/nipe" nocase ascii wide
                        $string9_nipe_offensive_tool_keyword = /nipe\.pl\s/ nocase ascii wide
                        $string10_nipe_offensive_tool_keyword = /perl\snipe\.pl\sinstall/ nocase ascii wide
                        $string11_nipe_offensive_tool_keyword = /perl\snipe\.pl\sstart/ nocase ascii wide
                        $string12_nipe_offensive_tool_keyword = "systemctl start tor" nocase ascii wide
                        $string13_nipe_offensive_tool_keyword = /tor\s\-f\s\.configs\/.{0,1000}\-torrc/ nocase ascii wide

    condition:
        any of them
}