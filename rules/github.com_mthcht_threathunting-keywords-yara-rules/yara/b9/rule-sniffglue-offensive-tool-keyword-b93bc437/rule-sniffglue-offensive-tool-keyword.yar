rule rule_sniffglue_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sniffglue' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sniffglue"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sniffglue_offensive_tool_keyword = "sniffglue" nocase ascii wide

    condition:
        any of them
}