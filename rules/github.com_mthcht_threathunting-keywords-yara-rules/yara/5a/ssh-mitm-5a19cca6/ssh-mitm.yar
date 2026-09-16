rule ssh_mitm
{
    meta:
        description = "Detection patterns for the tool 'ssh-mitm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh-mitm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "ssh-mitm" nocase ascii wide

    condition:
        any of them
}