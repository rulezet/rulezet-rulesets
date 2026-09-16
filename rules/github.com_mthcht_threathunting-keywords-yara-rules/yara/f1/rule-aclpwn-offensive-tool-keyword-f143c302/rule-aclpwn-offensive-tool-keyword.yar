rule rule_Aclpwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Aclpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Aclpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Aclpwn_offensive_tool_keyword = /aclpwn\.py/ nocase ascii wide

    condition:
        any of them
}