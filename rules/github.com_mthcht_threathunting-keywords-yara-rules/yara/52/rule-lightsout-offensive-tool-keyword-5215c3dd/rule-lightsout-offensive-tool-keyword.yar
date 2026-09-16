rule rule_LightsOut_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LightsOut' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LightsOut"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LightsOut_offensive_tool_keyword = /\/LightsOut\.git/ nocase ascii wide
                        $string2_LightsOut_offensive_tool_keyword = "icyguider/LightsOut" nocase ascii wide
                        $string3_LightsOut_offensive_tool_keyword = /lightsout\.py/ nocase ascii wide
                        $string4_LightsOut_offensive_tool_keyword = /LightsOut\-master\.zip/ nocase ascii wide

    condition:
        any of them
}