rule RoguePotato
{
    meta:
        description = "Detection patterns for the tool 'RoguePotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RoguePotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RoguePotato\.git/ nocase ascii wide
                        $string2 = "105C2C6D-1C0A-4535-A231-80E355EFB112" nocase ascii wide
                        $string3 = "61CE6716-E619-483C-B535-8694F7617548" nocase ascii wide
                        $string4 = "antonioCoco/RoguePotato" nocase ascii wide
                        $string5 = /RogueOxidResolver\.cpp/ nocase ascii wide
                        $string6 = /RoguePotato\.cpp/ nocase ascii wide
                        $string7 = /RoguePotato\.exe/ nocase ascii wide
                        $string8 = /RoguePotato\.sln/ nocase ascii wide
                        $string9 = /RoguePotato\.zip/ nocase ascii wide
                        $string10 = "RoguePotato-master" nocase ascii wide
                        $string11 = /TokenKidnapping\.cpp/ nocase ascii wide

    condition:
        any of them
}