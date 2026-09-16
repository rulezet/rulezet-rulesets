rule UniversalDVC
{
    meta:
        description = "Detection patterns for the tool 'UniversalDVC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UniversalDVC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /UDVC\-Server\.exe\s\-c\s.{0,1000}\s\-i\s127\.0\.0\.1/ nocase ascii wide

    condition:
        any of them
}