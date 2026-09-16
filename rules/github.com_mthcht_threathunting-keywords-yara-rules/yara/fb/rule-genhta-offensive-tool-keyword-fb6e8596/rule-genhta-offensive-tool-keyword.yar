rule rule_genHTA_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'genHTA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "genHTA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_genHTA_offensive_tool_keyword = "/genHTA"

    condition:
        any of them
}