rule rule_HideProcess_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HideProcess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HideProcess"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HideProcess_offensive_tool_keyword = "landhb/HideProcess" nocase ascii wide

    condition:
        any of them
}