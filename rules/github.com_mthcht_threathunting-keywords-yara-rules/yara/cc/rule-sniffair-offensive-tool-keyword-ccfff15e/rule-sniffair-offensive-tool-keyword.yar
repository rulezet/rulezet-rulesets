rule rule_SniffAir_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SniffAir' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffAir"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SniffAir_offensive_tool_keyword = "SniffAir" nocase ascii wide

    condition:
        any of them
}