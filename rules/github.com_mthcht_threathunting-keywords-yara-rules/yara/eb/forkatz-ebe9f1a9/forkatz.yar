rule forkatz
{
    meta:
        description = "Detection patterns for the tool 'forkatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "forkatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/forkatz\.filters/ nocase ascii wide
                        $string2 = /\/forkatz\.git/ nocase ascii wide
                        $string3 = /forkatz\.exe/ nocase ascii wide
                        $string4 = /forkatz\.sln/ nocase ascii wide
                        $string5 = /forkatz\.vcxproj/ nocase ascii wide
                        $string6 = "forkatz-main" nocase ascii wide
                        $string7 = /users\\public\\example\.bin/ nocase ascii wide
                        $string8 = /users\\public\\temp\.bin/ nocase ascii wide

    condition:
        any of them
}