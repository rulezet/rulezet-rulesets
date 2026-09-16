rule rule_RainbowCrack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RainbowCrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RainbowCrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RainbowCrack_offensive_tool_keyword = "RainbowCrack" nocase ascii wide

    condition:
        any of them
}