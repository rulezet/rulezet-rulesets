rule rule_prometheus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'prometheus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prometheus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_prometheus_offensive_tool_keyword = "/0xdarkvortex-" nocase ascii wide
                        $string2_prometheus_offensive_tool_keyword = "/paranoidninja/" nocase ascii wide
                        $string3_prometheus_offensive_tool_keyword = /\/prometheus\.exe/ nocase ascii wide
                        $string4_prometheus_offensive_tool_keyword = "0xdarkvortex-MalwareDevelopment" nocase ascii wide

    condition:
        any of them
}