rule rule_awesome_osint_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'awesome-osint' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-osint"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_awesome_osint_offensive_tool_keyword = "awesome-osint" nocase ascii wide

    condition:
        any of them
}