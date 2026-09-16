rule rule_Jormungandr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Jormungandr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jormungandr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Jormungandr_offensive_tool_keyword = /\/Jormungandr\.git/ nocase ascii wide
                        $string2_Jormungandr_offensive_tool_keyword = /\\\\\?\?\\\\Jormungandr/ nocase ascii wide
                        $string3_Jormungandr_offensive_tool_keyword = /COFFLdr\.cpp/ nocase ascii wide
                        $string4_Jormungandr_offensive_tool_keyword = /COFFLdr\.exe/ nocase ascii wide
                        $string5_Jormungandr_offensive_tool_keyword = "Idov31/Jormungandr" nocase ascii wide
                        $string6_Jormungandr_offensive_tool_keyword = /Jormungandr\.cpp/ nocase ascii wide
                        $string7_Jormungandr_offensive_tool_keyword = /Jormungandr\.exe/ nocase ascii wide
                        $string8_Jormungandr_offensive_tool_keyword = "Jormungandr-master" nocase ascii wide

    condition:
        any of them
}