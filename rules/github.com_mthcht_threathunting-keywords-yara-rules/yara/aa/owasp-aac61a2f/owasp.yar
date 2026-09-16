rule OWASP
{
    meta:
        description = "Detection patterns for the tool 'OWASP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OWASP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/OWASP"

    condition:
        any of them
}