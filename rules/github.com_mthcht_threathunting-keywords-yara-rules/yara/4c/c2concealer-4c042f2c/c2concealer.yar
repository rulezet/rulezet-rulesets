rule C2concealer
{
    meta:
        description = "Detection patterns for the tool 'C2concealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2concealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -t C2concealer " nocase ascii wide
                        $string2 = "/C2concealer" nocase ascii wide
                        $string3 = "/cobaltstrike/c2lint"
                        $string4 = "/usr/share/cobaltstrike/"
                        $string5 = /\\C2concealer/ nocase ascii wide
                        $string6 = "C2concealer -" nocase ascii wide
                        $string7 = "C2concealer-master" nocase ascii wide
                        $string8 = /malleable\-c2\-randomizer\.py/ nocase ascii wide

    condition:
        any of them
}