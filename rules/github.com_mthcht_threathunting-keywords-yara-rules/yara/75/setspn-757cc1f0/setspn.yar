rule setspn
{
    meta:
        description = "Detection patterns for the tool 'setspn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "setspn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /setspn\.exe\s\-F\s\-Q\s.{0,1000}\// nocase ascii wide
                        $string2 = /setspn\.exe.{0,1000}\s\-T\s.{0,1000}\-Q\scifs\// nocase ascii wide

    condition:
        any of them
}