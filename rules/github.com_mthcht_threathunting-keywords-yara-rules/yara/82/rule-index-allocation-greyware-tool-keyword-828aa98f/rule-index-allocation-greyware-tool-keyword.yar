rule rule_index_allocation_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '$index_allocation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "$index_allocation"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_index_allocation_greyware_tool_keyword = /\.\.\.\:\:\$index_allocation/ nocase ascii wide
                        $string2_index_allocation_greyware_tool_keyword = /cd\s.{0,1000}\.\:\:\$index_allocation/ nocase ascii wide
                        $string3_index_allocation_greyware_tool_keyword = /md\s.{0,1000}\.\:\:\$index_allocation/ nocase ascii wide

    condition:
        any of them
}