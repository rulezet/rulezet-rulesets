rule rule_sqli_labs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sqli-labs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqli-labs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sqli_labs_offensive_tool_keyword = "Sqli-lab" nocase ascii wide

    condition:
        any of them
}