rule StackCrypt
{
    meta:
        description = "Detection patterns for the tool 'StackCrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StackCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/StackCrypt\.git/ nocase ascii wide
                        $string2 = "5A6F942E-888A-4CE1-A6FB-1AB8AE22AFFA" nocase ascii wide
                        $string3 = "StackCrypt-main" nocase ascii wide
                        $string4 = /StackEncrypt\.cpp/ nocase ascii wide
                        $string5 = /StackEncrypt\.exe/ nocase ascii wide
                        $string6 = /StackEncrypt\.sln/ nocase ascii wide
                        $string7 = /StackEncrypt\.vcxproj/ nocase ascii wide
                        $string8 = "TheD1rkMtr/StackCrypt" nocase ascii wide

    condition:
        any of them
}