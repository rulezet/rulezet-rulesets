rule rule_ShellGhost_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellGhost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellGhost"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellGhost_offensive_tool_keyword = /\/ShellGhost\.git/ nocase ascii wide
                        $string2_ShellGhost_offensive_tool_keyword = "lem0nSec/ShellGhost" nocase ascii wide
                        $string3_ShellGhost_offensive_tool_keyword = /ShellGhost\.dll/ nocase ascii wide
                        $string4_ShellGhost_offensive_tool_keyword = /ShellGhost\.exe/ nocase ascii wide
                        $string5_ShellGhost_offensive_tool_keyword = /ShellGhost\.sln/ nocase ascii wide
                        $string6_ShellGhost_offensive_tool_keyword = /ShellGhost\.vcxproj/ nocase ascii wide
                        $string7_ShellGhost_offensive_tool_keyword = /ShellGhost_mapping\.py/ nocase ascii wide
                        $string8_ShellGhost_offensive_tool_keyword = /ShellGhost\-master\.zip/ nocase ascii wide
                        $string9_ShellGhost_offensive_tool_keyword = /src\/ShellGhost\.c/ nocase ascii wide

    condition:
        any of them
}