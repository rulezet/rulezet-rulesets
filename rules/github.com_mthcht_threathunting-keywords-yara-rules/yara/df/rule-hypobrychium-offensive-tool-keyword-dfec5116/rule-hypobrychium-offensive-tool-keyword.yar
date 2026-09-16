rule rule_hypobrychium_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hypobrychium' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hypobrychium"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hypobrychium_offensive_tool_keyword = /\/hypobrychium\.git/ nocase ascii wide
                        $string2_hypobrychium_offensive_tool_keyword = "foxlox/hypobrychium" nocase ascii wide
                        $string3_hypobrychium_offensive_tool_keyword = /hypobrychium\.exe/ nocase ascii wide
                        $string4_hypobrychium_offensive_tool_keyword = "hypobrychium-main" nocase ascii wide

    condition:
        any of them
}