rule rule_hping3_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hping3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hping3"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hping3_offensive_tool_keyword = /hping3\s.{0,1000}\s\-\-flood\s\-\-frag\s\-\-spoof\s.{0,1000}\s\-\-destport/

    condition:
        any of them
}