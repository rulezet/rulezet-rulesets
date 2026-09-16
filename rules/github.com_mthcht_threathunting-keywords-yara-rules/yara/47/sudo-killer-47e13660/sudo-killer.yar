rule SUDO_KILLER
{
    meta:
        description = "Detection patterns for the tool 'SUDO_KILLER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SUDO_KILLER"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "SUDO_KILLER"

    condition:
        any of them
}