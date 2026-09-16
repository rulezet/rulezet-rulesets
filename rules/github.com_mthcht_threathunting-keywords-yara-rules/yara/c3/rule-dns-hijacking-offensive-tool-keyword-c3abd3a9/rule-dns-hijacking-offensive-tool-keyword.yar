rule rule_DNS_Hijacking_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DNS-Hijacking' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Hijacking"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DNS_Hijacking_offensive_tool_keyword = /\/DNS\-Hijacking\.git/
                        $string2_DNS_Hijacking_offensive_tool_keyword = "DyeKuu/DNS-Hijacking"

    condition:
        any of them
}