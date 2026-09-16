rule rule_NoSQLMap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NoSQLMap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoSQLMap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NoSQLMap_offensive_tool_keyword = "NoSQLMap"

    condition:
        any of them
}