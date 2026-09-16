rule rule_UniByAv_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UniByAv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UniByAv"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UniByAv_offensive_tool_keyword = "UniByAv" nocase ascii wide

    condition:
        any of them
}