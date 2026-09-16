rule rule_phoenix_miner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'phoenix miner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phoenix miner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_phoenix_miner_greyware_tool_keyword = /PhoenixMiner\.exe/ nocase ascii wide
                        $string2_phoenix_miner_greyware_tool_keyword = /PhoenixMiner_.{0,1000}_Windows\\/ nocase ascii wide

    condition:
        any of them
}