rule rule_NetworkMiner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetworkMiner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetworkMiner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NetworkMiner_offensive_tool_keyword = "NetworkMiner" nocase ascii wide

    condition:
        any of them
}