rule rule_HeapCrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HeapCrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HeapCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HeapCrypt_offensive_tool_keyword = /\/HeapCrypt\.git/ nocase ascii wide
                        $string2_HeapCrypt_offensive_tool_keyword = "83035080-7788-4EA3-82EE-6C06D2E6891F" nocase ascii wide
                        $string3_HeapCrypt_offensive_tool_keyword = "HeapCrypt-main" nocase ascii wide
                        $string4_HeapCrypt_offensive_tool_keyword = /HeapEncryptDecrypt\.cpp/ nocase ascii wide
                        $string5_HeapCrypt_offensive_tool_keyword = /HeapEncryptDecrypt\.exe/ nocase ascii wide
                        $string6_HeapCrypt_offensive_tool_keyword = /HeapEncryptDecrypt\.sln/ nocase ascii wide
                        $string7_HeapCrypt_offensive_tool_keyword = /HeapEncryptDecrypt\.vcxproj/ nocase ascii wide
                        $string8_HeapCrypt_offensive_tool_keyword = "TheD1rkMtr/HeapCrypt" nocase ascii wide

    condition:
        any of them
}