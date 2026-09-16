rule SilentMoonwalk
{
    meta:
        description = "Detection patterns for the tool 'SilentMoonwalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentMoonwalk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SilentMoonwalk\.git/ nocase ascii wide
                        $string2 = "E11DC25D-E96D-495D-8968-1BA09C95B673" nocase ascii wide
                        $string3 = "klezVirus/SilentMoonwalk" nocase ascii wide
                        $string4 = /SilentMoonwalk\.cpp/ nocase ascii wide
                        $string5 = /SilentMoonwalk\.exe/ nocase ascii wide
                        $string6 = /SilentMoonwalk\.sln/ nocase ascii wide
                        $string7 = "SilentMoonwalk-master" nocase ascii wide
                        $string8 = /UnwindInspector\.exe/ nocase ascii wide

    condition:
        any of them
}