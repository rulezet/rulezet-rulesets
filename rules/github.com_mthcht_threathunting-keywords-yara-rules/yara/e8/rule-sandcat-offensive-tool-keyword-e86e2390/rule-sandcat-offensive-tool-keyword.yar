rule rule_sandcat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sandcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sandcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sandcat_offensive_tool_keyword = /\/sandcat\.git/ nocase ascii wide
                        $string2_sandcat_offensive_tool_keyword = /syhunt\.com\/sandcat\// nocase ascii wide
                        $string3_sandcat_offensive_tool_keyword = "syhunt/sandcat" nocase ascii wide
                        $string4_sandcat_offensive_tool_keyword = /syhunt\-sandcat\-.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}