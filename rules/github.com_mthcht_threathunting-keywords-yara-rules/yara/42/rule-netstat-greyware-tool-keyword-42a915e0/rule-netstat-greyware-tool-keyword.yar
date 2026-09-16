rule rule_netstat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netstat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netstat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_netstat_greyware_tool_keyword = "netsat -naop" nocase ascii wide
                        $string2_netstat_greyware_tool_keyword = "netstat -ano" nocase ascii wide
                        $string3_netstat_greyware_tool_keyword = "netstat -ant" nocase ascii wide
                        $string4_netstat_greyware_tool_keyword = /NETSTAT\.EXE.{0,1000}\s\-ano/ nocase ascii wide

    condition:
        any of them
}