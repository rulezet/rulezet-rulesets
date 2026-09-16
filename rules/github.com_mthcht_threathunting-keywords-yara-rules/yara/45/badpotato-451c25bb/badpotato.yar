rule BadPotato
{
    meta:
        description = "Detection patterns for the tool 'BadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadPotato"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/BadPotato-A" nocase ascii wide
                        $string2 = /BadPotato\.Win32/ nocase ascii wide
                        $string3 = /HackTool\.BadPotato/ nocase ascii wide
                        $string4 = "HackTool/BadPotato" nocase ascii wide
                        $string5 = "HackTool:Win32/Badcastle!pz" nocase ascii wide

    condition:
        any of them
}