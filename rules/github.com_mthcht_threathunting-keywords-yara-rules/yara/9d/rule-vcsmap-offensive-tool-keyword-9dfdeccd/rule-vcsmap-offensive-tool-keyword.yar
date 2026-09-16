rule rule_vcsmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vcsmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vcsmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_vcsmap_offensive_tool_keyword = "vcsmap" nocase ascii wide

    condition:
        any of them
}