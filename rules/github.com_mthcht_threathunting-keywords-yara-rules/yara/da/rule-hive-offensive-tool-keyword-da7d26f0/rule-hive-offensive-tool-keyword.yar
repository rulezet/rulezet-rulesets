rule rule_Hive_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hive"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hive_offensive_tool_keyword = /HOW_TO_DECRYPT\.txt/ nocase ascii wide

    condition:
        any of them
}