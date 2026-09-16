rule rule_teamstracker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'teamstracker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamstracker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_teamstracker_offensive_tool_keyword = /\steamstracker\.py/ nocase ascii wide
                        $string2_teamstracker_offensive_tool_keyword = /\/teamstracker\.db/ nocase ascii wide
                        $string3_teamstracker_offensive_tool_keyword = /\/teamstracker\.git/ nocase ascii wide
                        $string4_teamstracker_offensive_tool_keyword = /\/teamstracker\.py/ nocase ascii wide
                        $string5_teamstracker_offensive_tool_keyword = /\\teamstracker\.py/ nocase ascii wide
                        $string6_teamstracker_offensive_tool_keyword = "nyxgeek/teamstracker" nocase ascii wide
                        $string7_teamstracker_offensive_tool_keyword = "teamstracker-main" nocase ascii wide

    condition:
        any of them
}