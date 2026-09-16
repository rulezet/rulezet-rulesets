rule rule_bropper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bropper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bropper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bropper_offensive_tool_keyword = /\sbropper\.py/ nocase ascii wide
                        $string2_bropper_offensive_tool_keyword = /\s\-t\s127\.0\.0\.1\s\-p\s1337\s/ nocase ascii wide
                        $string3_bropper_offensive_tool_keyword = /\.py\s.{0,1000}\s\-\-brop\s/ nocase ascii wide
                        $string4_bropper_offensive_tool_keyword = /\/Bropper\.git/ nocase ascii wide
                        $string5_bropper_offensive_tool_keyword = /\/bropper\.py/ nocase ascii wide
                        $string6_bropper_offensive_tool_keyword = /bropper\.py\s/ nocase ascii wide
                        $string7_bropper_offensive_tool_keyword = /Bropper\-main\.zip/ nocase ascii wide
                        $string8_bropper_offensive_tool_keyword = "--expected Bad --expected-stop Welcome" nocase ascii wide
                        $string9_bropper_offensive_tool_keyword = "Hakumarachi/Bropper" nocase ascii wide

    condition:
        any of them
}