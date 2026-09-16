rule rule_OWASP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OWASP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OWASP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OWASP_offensive_tool_keyword = "/OWASP"

    condition:
        any of them
}