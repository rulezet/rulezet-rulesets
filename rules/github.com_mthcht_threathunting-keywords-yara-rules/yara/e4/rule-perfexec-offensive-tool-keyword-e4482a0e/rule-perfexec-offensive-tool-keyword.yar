rule rule_PerfExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PerfExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PerfExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PerfExec_offensive_tool_keyword = /\sdiagrun\=true\sservice\=DNS.{0,1000}\sdllpath\=.{0,1000}\.dll.{0,1000}\scomputername\=/ nocase ascii wide
                        $string2_PerfExec_offensive_tool_keyword = /\swmirun\=true\sdllpath\=.{0,1000}\.dll.{0,1000}\scomputername\=/ nocase ascii wide
                        $string3_PerfExec_offensive_tool_keyword = /\\PerfExec\.exe/ nocase ascii wide
                        $string4_PerfExec_offensive_tool_keyword = "0xthirteen/PerfExec" nocase ascii wide
                        $string5_PerfExec_offensive_tool_keyword = /PerfExec\.sln/ nocase ascii wide
                        $string6_PerfExec_offensive_tool_keyword = /PerfExec\-main\.zip/ nocase ascii wide

    condition:
        any of them
}