rule rule_BadPotato_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'BadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadPotato"
        rule_category = "signature_keyword"

    strings:
                        $string1_BadPotato_signature_keyword = "ATK/BadPotato-A" nocase ascii wide
                        $string2_BadPotato_signature_keyword = /BadPotato\.Win32/ nocase ascii wide
                        $string3_BadPotato_signature_keyword = /HackTool\.BadPotato/ nocase ascii wide
                        $string4_BadPotato_signature_keyword = "HackTool/BadPotato" nocase ascii wide
                        $string5_BadPotato_signature_keyword = "HackTool:Win32/Badcastle!pz" nocase ascii wide

    condition:
        any of them
}