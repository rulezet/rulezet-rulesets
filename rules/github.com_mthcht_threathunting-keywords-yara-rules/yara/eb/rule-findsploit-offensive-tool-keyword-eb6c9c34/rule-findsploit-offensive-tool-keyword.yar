rule rule_Findsploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Findsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Findsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Findsploit_offensive_tool_keyword = "Findsploit" nocase ascii wide

    condition:
        any of them
}