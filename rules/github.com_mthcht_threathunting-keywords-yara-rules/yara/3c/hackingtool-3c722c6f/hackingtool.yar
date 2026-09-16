rule hackingtool
{
    meta:
        description = "Detection patterns for the tool 'hackingtool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackingtool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/hackingtool\.git/ nocase ascii wide
                        $string2 = /anonsurf\.py/ nocase ascii wide
                        $string3 = /exploit_frameworks\.py/ nocase ascii wide
                        $string4 = /hackingtool\.py/ nocase ascii wide
                        $string5 = /information_gathering_tools\.py/ nocase ascii wide
                        $string6 = /payload_creator\.py/ nocase ascii wide
                        $string7 = /phising_attack\.py/ nocase ascii wide
                        $string8 = /post_exploitation\.py/ nocase ascii wide
                        $string9 = /wireless_attack_tools\.py/ nocase ascii wide
                        $string10 = "Z4nzu/hackingtool" nocase ascii wide

    condition:
        any of them
}