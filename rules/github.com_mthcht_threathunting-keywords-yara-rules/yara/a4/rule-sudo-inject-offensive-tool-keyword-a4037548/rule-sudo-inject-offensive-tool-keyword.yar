rule rule_sudo_inject_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sudo_inject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo_inject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sudo_inject_offensive_tool_keyword = "sudo_inject"

    condition:
        any of them
}