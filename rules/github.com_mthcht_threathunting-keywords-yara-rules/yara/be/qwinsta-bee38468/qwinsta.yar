rule qwinsta
{
    meta:
        description = "Detection patterns for the tool 'qwinsta' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qwinsta"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cmd\s\/c\s.{0,1000}qwinsta/ nocase ascii wide
                        $string2 = /cmd\.exe.{0,1000}qwinsta/ nocase ascii wide
                        $string3 = "qwinsta /server:" nocase ascii wide

    condition:
        any of them
}