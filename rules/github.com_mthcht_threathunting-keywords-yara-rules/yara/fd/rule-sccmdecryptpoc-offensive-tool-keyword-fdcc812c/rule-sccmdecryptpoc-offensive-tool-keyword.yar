rule rule_sccmdecryptpoc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sccmdecryptpoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sccmdecryptpoc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sccmdecryptpoc_offensive_tool_keyword = /sccmdecryptpoc\./ nocase ascii wide

    condition:
        any of them
}