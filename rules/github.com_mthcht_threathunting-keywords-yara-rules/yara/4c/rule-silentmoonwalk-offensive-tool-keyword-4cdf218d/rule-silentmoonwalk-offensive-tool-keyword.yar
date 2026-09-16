rule rule_SilentMoonwalk_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SilentMoonwalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentMoonwalk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SilentMoonwalk_offensive_tool_keyword = /\/SilentMoonwalk\.git/ nocase ascii wide
                        $string2_SilentMoonwalk_offensive_tool_keyword = "E11DC25D-E96D-495D-8968-1BA09C95B673" nocase ascii wide
                        $string3_SilentMoonwalk_offensive_tool_keyword = "klezVirus/SilentMoonwalk" nocase ascii wide
                        $string4_SilentMoonwalk_offensive_tool_keyword = /SilentMoonwalk\.cpp/ nocase ascii wide
                        $string5_SilentMoonwalk_offensive_tool_keyword = /SilentMoonwalk\.exe/ nocase ascii wide
                        $string6_SilentMoonwalk_offensive_tool_keyword = /SilentMoonwalk\.sln/ nocase ascii wide
                        $string7_SilentMoonwalk_offensive_tool_keyword = "SilentMoonwalk-master" nocase ascii wide
                        $string8_SilentMoonwalk_offensive_tool_keyword = /UnwindInspector\.exe/ nocase ascii wide

    condition:
        any of them
}