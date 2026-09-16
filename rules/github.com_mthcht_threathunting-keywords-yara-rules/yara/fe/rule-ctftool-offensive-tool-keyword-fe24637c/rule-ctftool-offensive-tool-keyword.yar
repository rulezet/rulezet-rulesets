rule rule_ctftool_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ctftool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ctftool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ctftool_offensive_tool_keyword = "/ctftool" nocase ascii wide

    condition:
        any of them
}