rule rule_msfpc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'msfpc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msfpc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_msfpc_offensive_tool_keyword = /\/msfpc\.sh/ nocase ascii wide
                        $string2_msfpc_offensive_tool_keyword = /msfpc\.sh/ nocase ascii wide

    condition:
        any of them
}