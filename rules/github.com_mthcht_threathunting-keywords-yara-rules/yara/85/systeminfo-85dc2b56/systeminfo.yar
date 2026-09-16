rule systeminfo
{
    meta:
        description = "Detection patterns for the tool 'systeminfo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "systeminfo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "cmd /c systeminfo" nocase ascii wide
                        $string2 = /cmd\.exe\s\/c\ssysteminfo/ nocase ascii wide

    condition:
        any of them
}