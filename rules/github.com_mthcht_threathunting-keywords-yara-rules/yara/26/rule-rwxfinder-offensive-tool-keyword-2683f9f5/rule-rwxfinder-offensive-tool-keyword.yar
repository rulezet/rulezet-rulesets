rule rule_rwxfinder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rwxfinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rwxfinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rwxfinder_offensive_tool_keyword = /\/RWXfinder\.git/ nocase ascii wide
                        $string2_rwxfinder_offensive_tool_keyword = "pwnsauc3/RWXFinder" nocase ascii wide
                        $string3_rwxfinder_offensive_tool_keyword = /rwxfinder\./ nocase ascii wide
                        $string4_rwxfinder_offensive_tool_keyword = "RWXfinder-main" nocase ascii wide

    condition:
        any of them
}