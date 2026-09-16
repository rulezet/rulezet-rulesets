rule p0wny_shell
{
    meta:
        description = "Detection patterns for the tool 'p0wny-shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0wny-shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "p0wny-shell" nocase ascii wide

    condition:
        any of them
}