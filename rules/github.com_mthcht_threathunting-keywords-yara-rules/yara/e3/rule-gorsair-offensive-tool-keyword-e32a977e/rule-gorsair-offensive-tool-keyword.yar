rule rule_Gorsair_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gorsair' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gorsair"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Gorsair_offensive_tool_keyword = "/bin/gorsair "
                        $string2_Gorsair_offensive_tool_keyword = /\/gorsair\.go/ nocase ascii wide
                        $string3_Gorsair_offensive_tool_keyword = "gorsair -t " nocase ascii wide
                        $string4_Gorsair_offensive_tool_keyword = "Ullaakut/Gorsair" nocase ascii wide

    condition:
        any of them
}