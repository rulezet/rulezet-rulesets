rule gateway_finder_imp
{
    meta:
        description = "Detection patterns for the tool 'gateway-finder-imp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gateway-finder-imp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "gateway-finder" nocase ascii wide

    condition:
        any of them
}