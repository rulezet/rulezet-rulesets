rule polenum
{
    meta:
        description = "Detection patterns for the tool 'polenum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "polenum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spolenum\.py/ nocase ascii wide
                        $string2 = /\/polenum\.py/
                        $string3 = "/usr/bin/polenum"
                        $string4 = /\\polenum\.py/ nocase ascii wide
                        $string5 = "apt install polenum" nocase ascii wide
                        $string6 = /polenum\s.{0,1000}\-protocols\s/ nocase ascii wide
                        $string7 = "polenum -h" nocase ascii wide

    condition:
        any of them
}