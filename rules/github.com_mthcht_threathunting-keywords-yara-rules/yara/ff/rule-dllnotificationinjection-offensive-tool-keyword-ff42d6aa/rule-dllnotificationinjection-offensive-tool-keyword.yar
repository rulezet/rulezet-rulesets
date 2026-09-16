rule rule_DllNotificationInjection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DllNotificationInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllNotificationInjection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DllNotificationInjection_offensive_tool_keyword = /\/DllNotificationInjection\.git/ nocase ascii wide
                        $string2_DllNotificationInjection_offensive_tool_keyword = "0A1C2C46-33F7-4D4C-B8C6-1FC9B116A6DF" nocase ascii wide
                        $string3_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.cpp/ nocase ascii wide
                        $string4_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.exe/ nocase ascii wide
                        $string5_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.sln/ nocase ascii wide
                        $string6_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.vcxproj/ nocase ascii wide
                        $string7_DllNotificationInjection_offensive_tool_keyword = "DllNotificationInjection-master" nocase ascii wide
                        $string8_DllNotificationInjection_offensive_tool_keyword = /ShellcodeTemplate\.x64\.bin/ nocase ascii wide
                        $string9_DllNotificationInjection_offensive_tool_keyword = "ShorSec/DllNotificationInjection" nocase ascii wide

    condition:
        any of them
}