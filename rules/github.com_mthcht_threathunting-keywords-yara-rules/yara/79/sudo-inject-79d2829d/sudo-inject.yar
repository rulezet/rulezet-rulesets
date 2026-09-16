rule sudo_inject
{
    meta:
        description = "Detection patterns for the tool 'sudo_inject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo_inject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "sudo_inject"

    condition:
        any of them
}