rule rule_dnsenum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnsenum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsenum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnsenum_offensive_tool_keyword = /dnsenum\.pl/

    condition:
        any of them
}