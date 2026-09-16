rule rule_UnlinkDLL_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UnlinkDLL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnlinkDLL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UnlinkDLL_offensive_tool_keyword = /\/UnlinkDLL\.git/ nocase ascii wide
                        $string2_UnlinkDLL_offensive_tool_keyword = "frkngksl/UnlinkDLL" nocase ascii wide
                        $string3_UnlinkDLL_offensive_tool_keyword = /listdlls64\.exe/ nocase ascii wide
                        $string4_UnlinkDLL_offensive_tool_keyword = /MaliciousInjectedDll\.dll/ nocase ascii wide
                        $string5_UnlinkDLL_offensive_tool_keyword = /UnlinkDLL\.exe/ nocase ascii wide
                        $string6_UnlinkDLL_offensive_tool_keyword = /UnlinkDLL\\Main\.nim/ nocase ascii wide
                        $string7_UnlinkDLL_offensive_tool_keyword = /UnlinkDLL\\Structs\.nim/ nocase ascii wide
                        $string8_UnlinkDLL_offensive_tool_keyword = "UnlinkDLL-main" nocase ascii wide

    condition:
        any of them
}