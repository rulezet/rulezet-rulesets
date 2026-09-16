rule nipe
{
    meta:
        description = "Detection patterns for the tool 'nipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/etc\/init\.d\/tor\sstart/
                        $string2 = /\/etc\/init\.d\/tor\sstop/
                        $string3 = /\/nipe\.git/ nocase ascii wide
                        $string4 = /\/nipe\.pl/ nocase ascii wide
                        $string5 = "/var/run/tor/control"
                        $string6 = /\/var\/run\/tor\/tor\.pid/
                        $string7 = "htrgouvea/nipe" nocase ascii wide
                        $string8 = "htrgouvea/nipe" nocase ascii wide
                        $string9 = /nipe\.pl\s/ nocase ascii wide
                        $string10 = /perl\snipe\.pl\sinstall/ nocase ascii wide
                        $string11 = /perl\snipe\.pl\sstart/ nocase ascii wide
                        $string12 = "systemctl start tor" nocase ascii wide
                        $string13 = /tor\s\-f\s\.configs\/.{0,1000}\-torrc/ nocase ascii wide

    condition:
        any of them
}