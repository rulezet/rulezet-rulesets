rule rule_xxd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xxd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xxd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_xxd_greyware_tool_keyword = /xxd\s\-p\s\-c\s4\s\/.{0,1000}\s\|\swhile\sread\sline.{0,1000}\sdo\sping\s\-c\s1\s\-p\s/ nocase ascii wide

    condition:
        any of them
}