rule PerfExec
{
    meta:
        description = "Detection patterns for the tool 'PerfExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PerfExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdiagrun\=true\sservice\=DNS.{0,1000}\sdllpath\=.{0,1000}\.dll.{0,1000}\scomputername\=/ nocase ascii wide
                        $string2 = /\swmirun\=true\sdllpath\=.{0,1000}\.dll.{0,1000}\scomputername\=/ nocase ascii wide
                        $string3 = /\\PerfExec\.exe/ nocase ascii wide
                        $string4 = "0xthirteen/PerfExec" nocase ascii wide
                        $string5 = /PerfExec\.sln/ nocase ascii wide
                        $string6 = /PerfExec\-main\.zip/ nocase ascii wide

    condition:
        any of them
}