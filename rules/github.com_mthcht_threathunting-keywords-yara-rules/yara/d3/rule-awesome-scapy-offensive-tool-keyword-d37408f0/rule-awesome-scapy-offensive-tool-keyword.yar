rule rule_awesome_scapy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'awesome-scapy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-scapy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_awesome_scapy_offensive_tool_keyword = "awesome-scapy" nocase ascii wide

    condition:
        any of them
}