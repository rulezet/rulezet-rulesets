rule ShellGhost
{
    meta:
        description = "Detection patterns for the tool 'ShellGhost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellGhost"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ShellGhost\.git/ nocase ascii wide
                        $string2 = "lem0nSec/ShellGhost" nocase ascii wide
                        $string3 = /ShellGhost\.dll/ nocase ascii wide
                        $string4 = /ShellGhost\.exe/ nocase ascii wide
                        $string5 = /ShellGhost\.sln/ nocase ascii wide
                        $string6 = /ShellGhost\.vcxproj/ nocase ascii wide
                        $string7 = /ShellGhost_mapping\.py/ nocase ascii wide
                        $string8 = /ShellGhost\-master\.zip/ nocase ascii wide
                        $string9 = /src\/ShellGhost\.c/ nocase ascii wide

    condition:
        any of them
}