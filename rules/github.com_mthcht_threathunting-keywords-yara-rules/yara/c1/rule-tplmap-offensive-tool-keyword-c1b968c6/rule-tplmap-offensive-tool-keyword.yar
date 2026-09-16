rule rule_tplmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tplmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tplmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tplmap_offensive_tool_keyword = "tplmap" nocase ascii wide

    condition:
        any of them
}