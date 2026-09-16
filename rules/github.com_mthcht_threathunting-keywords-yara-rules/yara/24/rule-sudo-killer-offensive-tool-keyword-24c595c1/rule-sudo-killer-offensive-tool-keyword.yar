rule rule_SUDO_KILLER_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SUDO_KILLER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SUDO_KILLER"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SUDO_KILLER_offensive_tool_keyword = "SUDO_KILLER"

    condition:
        any of them
}