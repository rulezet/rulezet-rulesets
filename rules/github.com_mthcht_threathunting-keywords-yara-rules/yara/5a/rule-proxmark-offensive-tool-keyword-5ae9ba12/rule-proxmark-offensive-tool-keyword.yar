rule rule_Proxmark_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Proxmark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxmark"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Proxmark_offensive_tool_keyword = "/Proxmark3" nocase ascii wide

    condition:
        any of them
}