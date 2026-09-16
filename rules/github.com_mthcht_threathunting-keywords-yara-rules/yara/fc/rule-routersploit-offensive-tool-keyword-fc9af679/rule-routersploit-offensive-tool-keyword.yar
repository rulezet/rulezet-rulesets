rule rule_routersploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'routersploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "routersploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_routersploit_offensive_tool_keyword = "routersploit" nocase ascii wide

    condition:
        any of them
}