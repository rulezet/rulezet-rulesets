rule rule_dnsteal_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnsteal' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsteal"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnsteal_offensive_tool_keyword = "/dnsteal" nocase ascii wide
                        $string2_dnsteal_offensive_tool_keyword = /dnsteal\.git/ nocase ascii wide
                        $string3_dnsteal_offensive_tool_keyword = /dnsteal\.py/ nocase ascii wide
                        $string4_dnsteal_offensive_tool_keyword = "dnsteal-master" nocase ascii wide

    condition:
        any of them
}