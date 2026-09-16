rule rule_mars_stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mars stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mars stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mars_stealer_offensive_tool_keyword = /cmd\.exe\s\/c\stimeout\s\/t\s5\s\&\sdel\s\/f\s\/q\s.{0,1000}\%s.{0,1000}\s\&\sexit/ nocase ascii wide

    condition:
        any of them
}