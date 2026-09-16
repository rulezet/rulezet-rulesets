rule rule_KeyTabExtract_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KeyTabExtract' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyTabExtract"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KeyTabExtract_offensive_tool_keyword = "KeyTabExtract"

    condition:
        any of them
}