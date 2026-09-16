rule rule_ophcrack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ophcrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ophcrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ophcrack_offensive_tool_keyword = "ophcrack" nocase ascii wide

    condition:
        any of them
}