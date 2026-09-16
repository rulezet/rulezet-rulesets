rule rule_fuzzdb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fuzzdb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuzzdb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fuzzdb_offensive_tool_keyword = "fuzzdb" nocase ascii wide

    condition:
        any of them
}