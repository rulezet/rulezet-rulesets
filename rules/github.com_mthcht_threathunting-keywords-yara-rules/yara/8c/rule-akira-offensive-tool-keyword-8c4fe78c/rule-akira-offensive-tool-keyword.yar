rule rule_Akira_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Akira' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Akira"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Akira_offensive_tool_keyword = " :Failed to make full encrypt" nocase ascii wide
                        $string2_Akira_offensive_tool_keyword = "Paste this link - https://akira" nocase ascii wide

    condition:
        any of them
}