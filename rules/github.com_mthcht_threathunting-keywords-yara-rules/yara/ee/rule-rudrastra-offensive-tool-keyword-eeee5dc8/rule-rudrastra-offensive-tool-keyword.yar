rule rule_Rudrastra_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Rudrastra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rudrastra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Rudrastra_offensive_tool_keyword = /\/Rudrastra\.git/ nocase ascii wide
                        $string2_Rudrastra_offensive_tool_keyword = "aircrack-ng" nocase ascii wide
                        $string3_Rudrastra_offensive_tool_keyword = /fake_ap\.py/ nocase ascii wide
                        $string4_Rudrastra_offensive_tool_keyword = "install macchanger" nocase ascii wide
                        $string5_Rudrastra_offensive_tool_keyword = "macchanger -r" nocase ascii wide
                        $string6_Rudrastra_offensive_tool_keyword = /Rudrastra\-main\.zip/ nocase ascii wide
                        $string7_Rudrastra_offensive_tool_keyword = "SxNade/Rudrastra" nocase ascii wide

    condition:
        any of them
}