rule rule_TorPylle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TorPylle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TorPylle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TorPylle_offensive_tool_keyword = "TorPylle" nocase ascii wide

    condition:
        any of them
}