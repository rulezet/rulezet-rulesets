rule rule_dnsmorph_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnsmorph' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsmorph"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnsmorph_offensive_tool_keyword = "dnsmorph" nocase ascii wide

    condition:
        any of them
}