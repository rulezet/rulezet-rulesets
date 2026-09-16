rule ping_sweep
{
    meta:
        description = "Detection patterns for the tool 'ping-sweep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ping-sweep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "ping-sweep" nocase ascii wide

    condition:
        any of them
}