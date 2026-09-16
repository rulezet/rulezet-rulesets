rule rule_OpenSSH_Trojan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OpenSSH Trojan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OpenSSH Trojan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OpenSSH_Trojan_offensive_tool_keyword = /SSH\-2\.0\-OpenSSH_6\.7p2/ nocase ascii wide

    condition:
        any of them
}