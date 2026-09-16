rule rule_where_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'where' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "where"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_where_greyware_tool_keyword = /\swhere\s\/r\sC\:\\Windows\\WinSxS\\\s.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide

    condition:
        any of them
}