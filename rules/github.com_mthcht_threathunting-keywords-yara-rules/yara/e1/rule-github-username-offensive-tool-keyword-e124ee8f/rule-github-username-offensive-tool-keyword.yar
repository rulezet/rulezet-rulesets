rule rule_Github__Username_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Github  Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github  Username"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Github__Username_offensive_tool_keyword = "RhinoSecurityLabs" nocase ascii wide

    condition:
        any of them
}