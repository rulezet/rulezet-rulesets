rule genHTA
{
    meta:
        description = "Detection patterns for the tool 'genHTA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "genHTA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/genHTA"

    condition:
        any of them
}