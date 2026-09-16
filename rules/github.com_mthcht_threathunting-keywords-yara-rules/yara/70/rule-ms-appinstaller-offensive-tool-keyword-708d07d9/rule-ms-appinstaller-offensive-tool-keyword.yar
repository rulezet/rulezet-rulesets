rule rule_ms_appinstaller_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ms-appinstaller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ms-appinstaller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ms_appinstaller_offensive_tool_keyword = /start\sms\-appinstaller\:\/\/\?source\=https\:\/\/raw\.githubusercontent\.com/ nocase ascii wide

    condition:
        any of them
}