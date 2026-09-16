rule rule_macchanger_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'macchanger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macchanger"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_macchanger_greyware_tool_keyword = "macchanger -r " nocase ascii wide

    condition:
        any of them
}