rule rule_Vulmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Vulmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Vulmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Vulmap_offensive_tool_keyword = /\.\/vulmap\// nocase ascii wide
                        $string2_Vulmap_offensive_tool_keyword = /vulmon.{0,1000}Vulmap/

    condition:
        any of them
}