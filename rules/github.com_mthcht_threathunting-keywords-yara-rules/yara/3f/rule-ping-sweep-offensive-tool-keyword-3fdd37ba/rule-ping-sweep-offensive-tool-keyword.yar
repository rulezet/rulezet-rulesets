rule rule_ping_sweep_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ping-sweep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ping-sweep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ping_sweep_offensive_tool_keyword = "ping-sweep" nocase ascii wide

    condition:
        any of them
}