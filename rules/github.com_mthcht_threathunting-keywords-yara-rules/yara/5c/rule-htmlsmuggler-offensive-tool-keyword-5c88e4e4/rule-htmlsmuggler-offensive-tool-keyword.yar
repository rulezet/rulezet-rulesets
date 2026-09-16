rule rule_HTMLSmuggler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HTMLSmuggler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HTMLSmuggler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HTMLSmuggler_offensive_tool_keyword = /\/HTMLSmuggler\.git/ nocase ascii wide
                        $string2_HTMLSmuggler_offensive_tool_keyword = "/HTMLSmuggler/" nocase ascii wide
                        $string3_HTMLSmuggler_offensive_tool_keyword = /\\HTMLSmuggler\\/ nocase ascii wide
                        $string4_HTMLSmuggler_offensive_tool_keyword = "D00Movenok/HTMLSmuggler" nocase ascii wide
                        $string5_HTMLSmuggler_offensive_tool_keyword = "HTMLSmuggler-main" nocase ascii wide

    condition:
        any of them
}