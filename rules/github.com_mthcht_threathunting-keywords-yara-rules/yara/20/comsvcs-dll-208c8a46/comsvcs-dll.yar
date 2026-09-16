rule comsvcs_dll
{
    meta:
        description = "Detection patterns for the tool 'comsvcs.dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "comsvcs.dll"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /comsvcs\.dll.{0,1000}\#\+00024764/ nocase ascii wide
                        $string2 = /comsvcs\.dll.{0,1000}\#24/ nocase ascii wide
                        $string3 = /comsvcs\.dll.{0,1000}MiniDump.{0,1000}lsass.{0,1000}full/ nocase ascii wide

    condition:
        any of them
}