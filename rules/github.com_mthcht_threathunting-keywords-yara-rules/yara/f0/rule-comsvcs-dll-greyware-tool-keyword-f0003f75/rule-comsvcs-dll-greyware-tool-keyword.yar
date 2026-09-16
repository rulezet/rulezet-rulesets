rule rule_comsvcs_dll_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'comsvcs.dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "comsvcs.dll"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_comsvcs_dll_greyware_tool_keyword = /comsvcs\.dll.{0,1000}\#\+00024764/ nocase ascii wide
                        $string2_comsvcs_dll_greyware_tool_keyword = /comsvcs\.dll.{0,1000}\#24/ nocase ascii wide
                        $string3_comsvcs_dll_greyware_tool_keyword = /comsvcs\.dll.{0,1000}MiniDump.{0,1000}lsass.{0,1000}full/ nocase ascii wide

    condition:
        any of them
}