rule UnlinkDLL
{
    meta:
        description = "Detection patterns for the tool 'UnlinkDLL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnlinkDLL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/UnlinkDLL\.git/ nocase ascii wide
                        $string2 = "frkngksl/UnlinkDLL" nocase ascii wide
                        $string3 = /listdlls64\.exe/ nocase ascii wide
                        $string4 = /MaliciousInjectedDll\.dll/ nocase ascii wide
                        $string5 = /UnlinkDLL\.exe/ nocase ascii wide
                        $string6 = /UnlinkDLL\\Main\.nim/ nocase ascii wide
                        $string7 = /UnlinkDLL\\Structs\.nim/ nocase ascii wide
                        $string8 = "UnlinkDLL-main" nocase ascii wide

    condition:
        any of them
}