rule rule_byob_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'byob' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "byob"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_byob_offensive_tool_keyword = "malwaredllc" nocase ascii wide

    condition:
        any of them
}