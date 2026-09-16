rule rule_WorldWind_Stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WorldWind-Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WorldWind-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WorldWind_Stealer_offensive_tool_keyword = /WorldWind\sStealer\.zip/ nocase ascii wide
                        $string2_WorldWind_Stealer_offensive_tool_keyword = "WorldWind-Stealer" nocase ascii wide

    condition:
        any of them
}