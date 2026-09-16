rule rule_Hypnos_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hypnos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hypnos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hypnos_offensive_tool_keyword = /\/Hypnos\.git/ nocase ascii wide
                        $string2_Hypnos_offensive_tool_keyword = /\\Hypnos\.exe/ nocase ascii wide
                        $string3_Hypnos_offensive_tool_keyword = /\\Hypnos\.sln/ nocase ascii wide
                        $string4_Hypnos_offensive_tool_keyword = /\\Hypnos\.vcxproj/ nocase ascii wide
                        $string5_Hypnos_offensive_tool_keyword = /\\Hypnos\-main\\/ nocase ascii wide
                        $string6_Hypnos_offensive_tool_keyword = "CaptainNox/Hypnos" nocase ascii wide
                        $string7_Hypnos_offensive_tool_keyword = "D210570B-F1A0-4B66-9301-F7A54978C178" nocase ascii wide
                        $string8_Hypnos_offensive_tool_keyword = /Hypnos\-main\.zip/ nocase ascii wide

    condition:
        any of them
}