rule rule_egressbuster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'egressbuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "egressbuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_egressbuster_offensive_tool_keyword = "egressbuster" nocase ascii wide

    condition:
        any of them
}