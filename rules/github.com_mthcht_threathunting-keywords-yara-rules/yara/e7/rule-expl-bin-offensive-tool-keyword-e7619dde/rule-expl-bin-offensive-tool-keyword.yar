rule rule_expl_bin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'expl-bin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expl-bin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_expl_bin_offensive_tool_keyword = "expl-bin" nocase ascii wide

    condition:
        any of them
}