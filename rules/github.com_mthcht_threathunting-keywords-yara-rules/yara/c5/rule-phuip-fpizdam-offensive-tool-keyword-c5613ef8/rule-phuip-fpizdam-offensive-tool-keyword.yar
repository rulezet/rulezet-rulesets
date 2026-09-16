rule rule_phuip_fpizdam_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'phuip-fpizdam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phuip-fpizdam"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_phuip_fpizdam_offensive_tool_keyword = "phuip-fpizdam" nocase ascii wide

    condition:
        any of them
}