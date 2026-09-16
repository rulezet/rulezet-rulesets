rule iptables
{
    meta:
        description = "Detection patterns for the tool 'iptables' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iptables"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "chkconfig off ip6tables" nocase ascii wide
                        $string2 = "chkconfig off iptables" nocase ascii wide
                        $string3 = "iptables -A OUTPUT -p tcp --dport 514 -j DROP"
                        $string4 = "iptables -A OUTPUT -p tcp --dport 6514 -j DROP"
                        $string5 = "iptables -A OUTPUT -p udp --dport 514 -j DROP"
                        $string6 = "iptables -A OUTPUT -p udp --dport 6514 -j DROP"
                        $string7 = "service ip6tables stop" nocase ascii wide
                        $string8 = "service iptables stop" nocase ascii wide

    condition:
        any of them
}