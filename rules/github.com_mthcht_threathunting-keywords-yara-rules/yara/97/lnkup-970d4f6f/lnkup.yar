rule LNKUp
{
    meta:
        description = "Detection patterns for the tool 'LNKUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LNKUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.py\s\-\-host\s.{0,1000}\s\-\-type\sntlm\s\-\-output\s.{0,1000}\.lnk/ nocase ascii wide
                        $string2 = /\/LNKUp\.git/ nocase ascii wide
                        $string3 = /\/LNKUp\/generate\.py/ nocase ascii wide
                        $string4 = /\\LNKUp\\generate\.py/ nocase ascii wide
                        $string5 = /lnkup\.py\s\-\-/ nocase ascii wide
                        $string6 = "Plazmaz/LNKUp" nocase ascii wide

    condition:
        any of them
}