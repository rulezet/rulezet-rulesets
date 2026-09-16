rule rule_hackingtool_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hackingtool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackingtool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hackingtool_offensive_tool_keyword = /\/hackingtool\.git/ nocase ascii wide
                        $string2_hackingtool_offensive_tool_keyword = /anonsurf\.py/ nocase ascii wide
                        $string3_hackingtool_offensive_tool_keyword = /exploit_frameworks\.py/ nocase ascii wide
                        $string4_hackingtool_offensive_tool_keyword = /hackingtool\.py/ nocase ascii wide
                        $string5_hackingtool_offensive_tool_keyword = /information_gathering_tools\.py/ nocase ascii wide
                        $string6_hackingtool_offensive_tool_keyword = /payload_creator\.py/ nocase ascii wide
                        $string7_hackingtool_offensive_tool_keyword = /phising_attack\.py/ nocase ascii wide
                        $string8_hackingtool_offensive_tool_keyword = /post_exploitation\.py/ nocase ascii wide
                        $string9_hackingtool_offensive_tool_keyword = /wireless_attack_tools\.py/ nocase ascii wide
                        $string10_hackingtool_offensive_tool_keyword = "Z4nzu/hackingtool" nocase ascii wide

    condition:
        any of them
}