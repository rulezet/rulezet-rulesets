rule HeapCrypt
{
    meta:
        description = "Detection patterns for the tool 'HeapCrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HeapCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HeapCrypt\.git/ nocase ascii wide
                        $string2 = "83035080-7788-4EA3-82EE-6C06D2E6891F" nocase ascii wide
                        $string3 = "HeapCrypt-main" nocase ascii wide
                        $string4 = /HeapEncryptDecrypt\.cpp/ nocase ascii wide
                        $string5 = /HeapEncryptDecrypt\.exe/ nocase ascii wide
                        $string6 = /HeapEncryptDecrypt\.sln/ nocase ascii wide
                        $string7 = /HeapEncryptDecrypt\.vcxproj/ nocase ascii wide
                        $string8 = "TheD1rkMtr/HeapCrypt" nocase ascii wide

    condition:
        any of them
}