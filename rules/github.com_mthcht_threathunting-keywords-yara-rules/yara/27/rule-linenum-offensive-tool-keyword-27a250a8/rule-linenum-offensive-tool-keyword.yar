rule rule_LinEnum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LinEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LinEnum_offensive_tool_keyword = /\/LinEnum\.git/
                        $string2_LinEnum_offensive_tool_keyword = "/LinEnum/"
                        $string3_LinEnum_offensive_tool_keyword = /LinEnum\.sh/
                        $string4_LinEnum_offensive_tool_keyword = /LinEnum\-master\.ip/

    condition:
        any of them
}