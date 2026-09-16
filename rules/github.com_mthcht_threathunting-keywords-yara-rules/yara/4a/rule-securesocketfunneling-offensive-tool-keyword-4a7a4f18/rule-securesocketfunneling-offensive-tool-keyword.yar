rule rule_securesocketfunneling_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'securesocketfunneling' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "securesocketfunneling"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_securesocketfunneling_offensive_tool_keyword = "securesocketfunneling" nocase ascii wide

    condition:
        any of them
}