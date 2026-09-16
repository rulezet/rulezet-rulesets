rule rule_XSS_Payloads_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'XSS-Payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XSS-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_XSS_Payloads_offensive_tool_keyword = "XSS-Payloads" nocase ascii wide

    condition:
        any of them
}