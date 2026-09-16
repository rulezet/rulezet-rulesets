rule DllNotificationInjection
{
    meta:
        description = "Detection patterns for the tool 'DllNotificationInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllNotificationInjection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DllNotificationInjection\.git/ nocase ascii wide
                        $string2 = "0A1C2C46-33F7-4D4C-B8C6-1FC9B116A6DF" nocase ascii wide
                        $string3 = /DllNotificationInjection\.cpp/ nocase ascii wide
                        $string4 = /DllNotificationInjection\.exe/ nocase ascii wide
                        $string5 = /DllNotificationInjection\.sln/ nocase ascii wide
                        $string6 = /DllNotificationInjection\.vcxproj/ nocase ascii wide
                        $string7 = "DllNotificationInjection-master" nocase ascii wide
                        $string8 = /ShellcodeTemplate\.x64\.bin/ nocase ascii wide
                        $string9 = "ShorSec/DllNotificationInjection" nocase ascii wide

    condition:
        any of them
}