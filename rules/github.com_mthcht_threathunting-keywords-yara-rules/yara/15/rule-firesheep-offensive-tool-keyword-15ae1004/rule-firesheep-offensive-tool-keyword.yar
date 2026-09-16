rule rule_firesheep_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'firesheep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "firesheep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_firesheep_offensive_tool_keyword = "Firesheep/" nocase ascii wide

    condition:
        any of them
}