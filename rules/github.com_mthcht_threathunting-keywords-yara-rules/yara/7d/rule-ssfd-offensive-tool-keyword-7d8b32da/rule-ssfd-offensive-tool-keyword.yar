rule rule_ssfd_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ssfd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssfd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ssfd_offensive_tool_keyword = /ssf\.exe\s\-D\s.{0,1000}\s\-p\s.{0,1000}\s127\.0\.0\.1/ nocase ascii wide
                        $string2_ssfd_offensive_tool_keyword = /ssfd\.exe\s\-p\s/ nocase ascii wide

    condition:
        any of them
}