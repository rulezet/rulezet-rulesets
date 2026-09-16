rule rule_ip_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ip"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ip_greyware_tool_keyword = /ip\sl\sset\sdev\s.{0,1000}\saddress\s.{0,1000}\:.{0,1000}\:/ nocase ascii wide

    condition:
        any of them
}