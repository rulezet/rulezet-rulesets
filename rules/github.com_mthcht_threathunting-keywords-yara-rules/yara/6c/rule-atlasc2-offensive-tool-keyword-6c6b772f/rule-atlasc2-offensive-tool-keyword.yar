rule rule_AtlasC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AtlasC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AtlasC2_offensive_tool_keyword = /AtlasC2.{0,1000}APIModels/ nocase ascii wide
                        $string2_AtlasC2_offensive_tool_keyword = /AtlasC2.{0,1000}Client/ nocase ascii wide
                        $string3_AtlasC2_offensive_tool_keyword = /AtlasC2.{0,1000}implant/ nocase ascii wide
                        $string4_AtlasC2_offensive_tool_keyword = /AtlasC2.{0,1000}TeamServer/ nocase ascii wide
                        $string5_AtlasC2_offensive_tool_keyword = /AtlasC2\.exe/ nocase ascii wide
                        $string6_AtlasC2_offensive_tool_keyword = /AtlasC2b\.exe/ nocase ascii wide
                        $string7_AtlasC2_offensive_tool_keyword = /AtlasC2b\.sln/ nocase ascii wide
                        $string8_AtlasC2_offensive_tool_keyword = /AtlasImplant\.yar/ nocase ascii wide
                        $string9_AtlasC2_offensive_tool_keyword = "Gr1mmie/AtlasC2" nocase ascii wide

    condition:
        any of them
}