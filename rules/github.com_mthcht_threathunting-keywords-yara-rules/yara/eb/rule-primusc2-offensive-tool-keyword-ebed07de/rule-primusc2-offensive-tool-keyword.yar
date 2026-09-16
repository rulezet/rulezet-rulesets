rule rule_primusC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'primusC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "primusC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_primusC2_offensive_tool_keyword = /\/C2\/server\.py/ nocase ascii wide
                        $string2_primusC2_offensive_tool_keyword = "/PrimusC2" nocase ascii wide
                        $string3_primusC2_offensive_tool_keyword = /\/PrimusC2\.git/ nocase ascii wide
                        $string4_primusC2_offensive_tool_keyword = ":8999/Payloads/" nocase ascii wide
                        $string5_primusC2_offensive_tool_keyword = /127\.0\.0\.1\:4567/ nocase ascii wide
                        $string6_primusC2_offensive_tool_keyword = "localhost:4567" nocase ascii wide
                        $string7_primusC2_offensive_tool_keyword = /PrimusC2\-main\.zip/ nocase ascii wide
                        $string8_primusC2_offensive_tool_keyword = "SELECT displayName FROM AntiVirusProduct" nocase ascii wide
                        $string9_primusC2_offensive_tool_keyword = /ssh\s\-N\s\-R\s4567\:localhost\:.{0,1000}root/ nocase ascii wide

    condition:
        any of them
}