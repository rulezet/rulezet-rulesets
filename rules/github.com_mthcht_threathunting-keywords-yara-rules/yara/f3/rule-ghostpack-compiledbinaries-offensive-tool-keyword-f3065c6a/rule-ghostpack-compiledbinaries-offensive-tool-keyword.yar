rule rule_Ghostpack_CompiledBinaries_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ghostpack-CompiledBinaries' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ghostpack-CompiledBinaries"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ghostpack_CompiledBinaries_offensive_tool_keyword = "Ghostpack-CompiledBinaries" nocase ascii wide
                        $string2_Ghostpack_CompiledBinaries_offensive_tool_keyword = /RestrictedAdmin\.exe/ nocase ascii wide
                        $string3_Ghostpack_CompiledBinaries_offensive_tool_keyword = /SharpRoast\.exe/ nocase ascii wide

    condition:
        any of them
}