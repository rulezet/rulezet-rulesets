rule rule_netsh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_netsh_offensive_tool_keyword = /netsh.{0,1000}\sfirewall\sset\sopmode\sdisable/ nocase ascii wide

    condition:
        any of them
}