rule rule_Bat_Potato_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Bat-Potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bat-Potato"
        rule_category = "signature_keyword"

    strings:
                        $string1_Bat_Potato_signature_keyword = /\\Bat\-Potato\.bat/ nocase ascii wide
                        $string2_Bat_Potato_signature_keyword = "ATK/JPotato-" nocase ascii wide
                        $string3_Bat_Potato_signature_keyword = /HackTool\.JuicyPotato/ nocase ascii wide
                        $string4_Bat_Potato_signature_keyword = /HackTool\.Win64\.JPotato/ nocase ascii wide
                        $string5_Bat_Potato_signature_keyword = "HackTool:Win64/JuicyPotato" nocase ascii wide

    condition:
        any of them
}