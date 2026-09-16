rule rule_hashcat_rule_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hashcat-rule' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashcat-rule"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hashcat_offensive_tool_keyword = /\/hashcat\-rule\.git/
                        $string2_hashcat_offensive_tool_keyword = /\/password_ruled\.txt/
                        $string3_hashcat_offensive_tool_keyword = "clem9669/hashcat-rule"
                        $string4_hashcat_offensive_tool_keyword = /clem9669_case\.rule/
                        $string5_hashcat_offensive_tool_keyword = /clem9669_large\.rule/
                        $string6_hashcat_offensive_tool_keyword = /clem9669_medium\.rule/
                        $string7_hashcat_offensive_tool_keyword = /clem9669_small\.rule/
                        $string8_hashcat_offensive_tool_keyword = "hashcat-rule-master"

    condition:
        any of them
}