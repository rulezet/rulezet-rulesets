rule rule_DNSTracer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DNSTracer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNSTracer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DNSTracer_offensive_tool_keyword = "dnstracer" nocase ascii wide

    condition:
        any of them
}