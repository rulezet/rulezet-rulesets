rule rule_Mr_SIP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Mr.SIP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mr.SIP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Mr_SIP_offensive_tool_keyword = /meliht\/Mr\.SIP/ nocase ascii wide

    condition:
        any of them
}