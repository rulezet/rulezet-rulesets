rule rule_FluxionNetwork_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FluxionNetwork' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FluxionNetwork"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FluxionNetwork_offensive_tool_keyword = "FluxionNetwork" nocase ascii wide

    condition:
        any of them
}