rule rule_forkatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'forkatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "forkatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_forkatz_offensive_tool_keyword = /\/forkatz\.filters/ nocase ascii wide
                        $string2_forkatz_offensive_tool_keyword = /\/forkatz\.git/ nocase ascii wide
                        $string3_forkatz_offensive_tool_keyword = /forkatz\.exe/ nocase ascii wide
                        $string4_forkatz_offensive_tool_keyword = /forkatz\.sln/ nocase ascii wide
                        $string5_forkatz_offensive_tool_keyword = /forkatz\.vcxproj/ nocase ascii wide
                        $string6_forkatz_offensive_tool_keyword = "forkatz-main" nocase ascii wide
                        $string7_forkatz_offensive_tool_keyword = /users\\public\\example\.bin/ nocase ascii wide
                        $string8_forkatz_offensive_tool_keyword = /users\\public\\temp\.bin/ nocase ascii wide

    condition:
        any of them
}