rule sandcat
{
    meta:
        description = "Detection patterns for the tool 'sandcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sandcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sandcat\.git/ nocase ascii wide
                        $string2 = /syhunt\.com\/sandcat\// nocase ascii wide
                        $string3 = "syhunt/sandcat" nocase ascii wide
                        $string4 = /syhunt\-sandcat\-.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}