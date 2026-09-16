rule rule_PhoneInfoga_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PhoneInfoga' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhoneInfoga"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PhoneInfoga_offensive_tool_keyword = "PhoneInfoga" nocase ascii wide

    condition:
        any of them
}