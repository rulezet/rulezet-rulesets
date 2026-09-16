rule rule_gateway_finder_imp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gateway-finder-imp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gateway-finder-imp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gateway_finder_imp_offensive_tool_keyword = "gateway-finder" nocase ascii wide

    condition:
        any of them
}