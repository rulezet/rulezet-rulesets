rule PrivilegeEscalation
{
    meta:
        description = "Detection patterns for the tool 'PrivilegeEscalation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivilegeEscalation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "PrivilegeEscalation" nocase ascii wide

    condition:
        any of them
}