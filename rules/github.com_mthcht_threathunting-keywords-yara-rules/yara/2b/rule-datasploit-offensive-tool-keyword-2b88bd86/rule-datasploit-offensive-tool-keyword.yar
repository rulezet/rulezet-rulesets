rule rule_datasploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'datasploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "datasploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_datasploit_offensive_tool_keyword = "DataSploit" nocase ascii wide

    condition:
        any of them
}