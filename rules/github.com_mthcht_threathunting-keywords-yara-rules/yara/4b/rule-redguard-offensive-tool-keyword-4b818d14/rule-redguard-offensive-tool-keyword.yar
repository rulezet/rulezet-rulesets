rule rule_RedGuard_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RedGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RedGuard_offensive_tool_keyword = /\.\/RedGuard/
                        $string2_RedGuard_offensive_tool_keyword = /\/RedGuard\.git/ nocase ascii wide
                        $string3_RedGuard_offensive_tool_keyword = /\/RedGuard\.go/ nocase ascii wide
                        $string4_RedGuard_offensive_tool_keyword = "/RedGuard_32" nocase ascii wide
                        $string5_RedGuard_offensive_tool_keyword = "/RedGuard_64" nocase ascii wide
                        $string6_RedGuard_offensive_tool_keyword = "/wikiZ/RedGuard" nocase ascii wide
                        $string7_RedGuard_offensive_tool_keyword = /\\RedGuard\s\-/ nocase ascii wide
                        $string8_RedGuard_offensive_tool_keyword = "866e5289337ab033f89bc57c5274c7ca" nocase ascii wide
                        $string9_RedGuard_offensive_tool_keyword = /OverrideLHOST\s360\.com/ nocase ascii wide
                        $string10_RedGuard_offensive_tool_keyword = /RedGuard\.log/ nocase ascii wide
                        $string11_RedGuard_offensive_tool_keyword = "RedGuard/core" nocase ascii wide
                        $string12_RedGuard_offensive_tool_keyword = /RedGuard_x64\.exe/ nocase ascii wide
                        $string13_RedGuard_offensive_tool_keyword = /RedGuard_x86\.exe/ nocase ascii wide

    condition:
        any of them
}