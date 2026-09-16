rule sshLooterC
{
    meta:
        description = "Detection patterns for the tool 'sshLooterC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshLooterC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "sshLooterC" nocase ascii wide

    condition:
        any of them
}