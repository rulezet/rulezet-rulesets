rule rule_passwordfox_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_passwordfox_offensive_tool_keyword = /\/utils\/passwordfox\.html/ nocase ascii wide
                        $string2_passwordfox_offensive_tool_keyword = ">PasswordFox<" nocase ascii wide
                        $string3_passwordfox_offensive_tool_keyword = ">Password-Recovery For Firefox<" nocase ascii wide
                        $string4_passwordfox_offensive_tool_keyword = "22c75c356f7e3a118f3fb98fe16c5c9232e3834e631ea1bb2af6a923f57b7b0b" nocase ascii wide
                        $string5_passwordfox_offensive_tool_keyword = "faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395" nocase ascii wide
                        $string6_passwordfox_offensive_tool_keyword = /passwordfox\.exe/ nocase ascii wide
                        $string7_passwordfox_offensive_tool_keyword = /passwordfox\.zip/ nocase ascii wide
                        $string8_passwordfox_offensive_tool_keyword = /passwordfox\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}