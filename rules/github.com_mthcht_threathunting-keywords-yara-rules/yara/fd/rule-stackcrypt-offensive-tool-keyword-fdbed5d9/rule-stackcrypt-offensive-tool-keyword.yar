rule rule_StackCrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'StackCrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StackCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_StackCrypt_offensive_tool_keyword = /\/StackCrypt\.git/ nocase ascii wide
                        $string2_StackCrypt_offensive_tool_keyword = "5A6F942E-888A-4CE1-A6FB-1AB8AE22AFFA" nocase ascii wide
                        $string3_StackCrypt_offensive_tool_keyword = "StackCrypt-main" nocase ascii wide
                        $string4_StackCrypt_offensive_tool_keyword = /StackEncrypt\.cpp/ nocase ascii wide
                        $string5_StackCrypt_offensive_tool_keyword = /StackEncrypt\.exe/ nocase ascii wide
                        $string6_StackCrypt_offensive_tool_keyword = /StackEncrypt\.sln/ nocase ascii wide
                        $string7_StackCrypt_offensive_tool_keyword = /StackEncrypt\.vcxproj/ nocase ascii wide
                        $string8_StackCrypt_offensive_tool_keyword = "TheD1rkMtr/StackCrypt" nocase ascii wide

    condition:
        any of them
}