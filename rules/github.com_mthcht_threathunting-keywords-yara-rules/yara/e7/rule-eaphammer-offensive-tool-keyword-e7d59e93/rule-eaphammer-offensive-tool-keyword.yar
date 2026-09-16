rule rule_EAPHammer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EAPHammer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EAPHammer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EAPHammer_offensive_tool_keyword = "eaphammer" nocase ascii wide

    condition:
        any of them
}