rule seatbelt
{
    meta:
        description = "Detection patterns for the tool 'seatbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "seatbelt"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/Seatbelt-A" nocase ascii wide
                        $string2 = /HackTool\.MSIL\.Seatbelt/ nocase ascii wide
                        $string3 = /Hacktool\.Seatbelt/ nocase ascii wide
                        $string4 = /Win\.Packed\.Seatbelt\-/ nocase ascii wide
                        $string5 = /Windows\.Hacktool\.Seatbelt/ nocase ascii wide

    condition:
        any of them
}