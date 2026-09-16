rule rule_I2P_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'I2P' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "I2P"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_I2P_offensive_tool_keyword = "i2pinstall" nocase ascii wide

    condition:
        any of them
}