rule DarkLoadLibrary
{
    meta:
        description = "Detection patterns for the tool 'DarkLoadLibrary' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DarkLoadLibrary"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DarkLoadLibrary\.git/ nocase ascii wide
                        $string2 = /\\DarkLoadLibrary\./ nocase ascii wide
                        $string3 = "bats3c/DarkLoadLibrary" nocase ascii wide
                        $string4 = "DarkLoadLibrary-maser" nocase ascii wide

    condition:
        any of them
}