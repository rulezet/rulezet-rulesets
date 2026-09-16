rule rwxfinder
{
    meta:
        description = "Detection patterns for the tool 'rwxfinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rwxfinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RWXfinder\.git/ nocase ascii wide
                        $string2 = "pwnsauc3/RWXFinder" nocase ascii wide
                        $string3 = /rwxfinder\./ nocase ascii wide
                        $string4 = "RWXfinder-main" nocase ascii wide

    condition:
        any of them
}