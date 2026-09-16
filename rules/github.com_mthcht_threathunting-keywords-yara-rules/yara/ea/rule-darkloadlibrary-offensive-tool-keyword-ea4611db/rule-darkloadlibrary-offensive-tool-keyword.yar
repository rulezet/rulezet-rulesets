rule rule_DarkLoadLibrary_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DarkLoadLibrary' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DarkLoadLibrary"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DarkLoadLibrary_offensive_tool_keyword = /\/DarkLoadLibrary\.git/ nocase ascii wide
                        $string2_DarkLoadLibrary_offensive_tool_keyword = /\\DarkLoadLibrary\./ nocase ascii wide
                        $string3_DarkLoadLibrary_offensive_tool_keyword = "bats3c/DarkLoadLibrary" nocase ascii wide
                        $string4_DarkLoadLibrary_offensive_tool_keyword = "DarkLoadLibrary-maser" nocase ascii wide

    condition:
        any of them
}