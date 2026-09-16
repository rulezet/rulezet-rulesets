rule rule_dnsrecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnsrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsrecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnsrecon_offensive_tool_keyword = /\s\-d\s.{0,1000}\s\-t\szonewalk/
                        $string2_dnsrecon_offensive_tool_keyword = "dnsrecon"

    condition:
        any of them
}