rule rule_RogueSploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RogueSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RogueSploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RogueSploit_offensive_tool_keyword = "RogueSploit" nocase ascii wide

    condition:
        any of them
}