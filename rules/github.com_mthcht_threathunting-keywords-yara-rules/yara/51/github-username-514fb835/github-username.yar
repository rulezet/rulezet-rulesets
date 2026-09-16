rule Github__Username
{
    meta:
        description = "Detection patterns for the tool 'Github  Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github  Username"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "RhinoSecurityLabs" nocase ascii wide

    condition:
        any of them
}