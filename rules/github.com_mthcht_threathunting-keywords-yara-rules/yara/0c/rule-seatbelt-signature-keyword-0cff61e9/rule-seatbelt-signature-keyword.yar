rule rule_seatbelt_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'seatbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "seatbelt"
        rule_category = "signature_keyword"

    strings:
                        $string1_seatbelt_signature_keyword = "ATK/Seatbelt-A" nocase ascii wide
                        $string2_seatbelt_signature_keyword = /HackTool\.MSIL\.Seatbelt/ nocase ascii wide
                        $string3_seatbelt_signature_keyword = /Hacktool\.Seatbelt/ nocase ascii wide
                        $string4_seatbelt_signature_keyword = /Win\.Packed\.Seatbelt\-/ nocase ascii wide
                        $string5_seatbelt_signature_keyword = /Windows\.Hacktool\.Seatbelt/ nocase ascii wide

    condition:
        any of them
}