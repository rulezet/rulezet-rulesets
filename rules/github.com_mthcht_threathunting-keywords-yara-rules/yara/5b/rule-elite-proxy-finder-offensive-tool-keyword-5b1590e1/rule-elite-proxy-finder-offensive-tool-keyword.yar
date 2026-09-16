rule rule_elite_proxy_finder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'elite-proxy-finder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elite-proxy-finder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_elite_proxy_finder_offensive_tool_keyword = "elite-proxy-finder" nocase ascii wide

    condition:
        any of them
}