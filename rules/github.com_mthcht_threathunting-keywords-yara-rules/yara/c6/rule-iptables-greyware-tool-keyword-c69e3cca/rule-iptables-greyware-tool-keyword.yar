rule rule_iptables_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'iptables' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iptables"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_iptables_greyware_tool_keyword = "chkconfig off ip6tables" nocase ascii wide
                        $string2_iptables_greyware_tool_keyword = "chkconfig off iptables" nocase ascii wide
                        $string3_iptables_greyware_tool_keyword = "iptables -A OUTPUT -p tcp --dport 514 -j DROP"
                        $string4_iptables_greyware_tool_keyword = "iptables -A OUTPUT -p tcp --dport 6514 -j DROP"
                        $string5_iptables_greyware_tool_keyword = "iptables -A OUTPUT -p udp --dport 514 -j DROP"
                        $string6_iptables_greyware_tool_keyword = "iptables -A OUTPUT -p udp --dport 6514 -j DROP"
                        $string7_iptables_greyware_tool_keyword = "service ip6tables stop" nocase ascii wide
                        $string8_iptables_greyware_tool_keyword = "service iptables stop" nocase ascii wide

    condition:
        any of them
}