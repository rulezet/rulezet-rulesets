rule rule_sshLooterC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshLooterC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshLooterC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sshLooterC_offensive_tool_keyword = "sshLooterC" nocase ascii wide

    condition:
        any of them
}