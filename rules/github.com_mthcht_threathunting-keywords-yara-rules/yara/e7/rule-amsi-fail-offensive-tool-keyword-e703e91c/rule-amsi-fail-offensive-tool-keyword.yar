rule rule_amsi_fail_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'amsi.fail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "amsi.fail"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_amsi_fail_offensive_tool_keyword = /https\:\/\/amsi\.fail\// nocase ascii wide

    condition:
        any of them
}