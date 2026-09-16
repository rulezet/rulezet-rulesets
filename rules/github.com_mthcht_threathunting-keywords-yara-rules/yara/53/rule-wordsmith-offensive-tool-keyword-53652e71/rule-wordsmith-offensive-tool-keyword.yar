rule rule_wordsmith_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wordsmith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wordsmith"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wordsmith_offensive_tool_keyword = /skahwah.{0,1000}wordsmith/ nocase ascii wide

    condition:
        any of them
}