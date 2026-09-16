rule rule_LogonTracer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LogonTracer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LogonTracer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LogonTracer_offensive_tool_keyword = "LogonTracer" nocase ascii wide

    condition:
        any of them
}