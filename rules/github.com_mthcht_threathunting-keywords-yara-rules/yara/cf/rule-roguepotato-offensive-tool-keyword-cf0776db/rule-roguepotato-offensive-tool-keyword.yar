rule rule_RoguePotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RoguePotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RoguePotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RoguePotato_offensive_tool_keyword = /\/RoguePotato\.git/ nocase ascii wide
                        $string2_RoguePotato_offensive_tool_keyword = "105C2C6D-1C0A-4535-A231-80E355EFB112" nocase ascii wide
                        $string3_RoguePotato_offensive_tool_keyword = "61CE6716-E619-483C-B535-8694F7617548" nocase ascii wide
                        $string4_RoguePotato_offensive_tool_keyword = "antonioCoco/RoguePotato" nocase ascii wide
                        $string5_RoguePotato_offensive_tool_keyword = /RogueOxidResolver\.cpp/ nocase ascii wide
                        $string6_RoguePotato_offensive_tool_keyword = /RoguePotato\.cpp/ nocase ascii wide
                        $string7_RoguePotato_offensive_tool_keyword = /RoguePotato\.exe/ nocase ascii wide
                        $string8_RoguePotato_offensive_tool_keyword = /RoguePotato\.sln/ nocase ascii wide
                        $string9_RoguePotato_offensive_tool_keyword = /RoguePotato\.zip/ nocase ascii wide
                        $string10_RoguePotato_offensive_tool_keyword = "RoguePotato-master" nocase ascii wide
                        $string11_RoguePotato_offensive_tool_keyword = /TokenKidnapping\.cpp/ nocase ascii wide

    condition:
        any of them
}