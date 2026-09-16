rule rule_GhostPack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GhostPack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostPack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GhostPack_offensive_tool_keyword = "GhostPack" nocase ascii wide

    condition:
        any of them
}