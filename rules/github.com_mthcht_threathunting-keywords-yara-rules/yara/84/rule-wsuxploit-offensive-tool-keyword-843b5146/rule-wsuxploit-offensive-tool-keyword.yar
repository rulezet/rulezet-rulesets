rule rule_wsuxploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wsuxploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wsuxploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wsuxploit_offensive_tool_keyword = "wsuxploit" nocase ascii wide

    condition:
        any of them
}