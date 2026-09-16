rule rule_mimikittenz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mimikittenz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikittenz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mimikittenz_offensive_tool_keyword = "mimikittenz" nocase ascii wide

    condition:
        any of them
}