rule rule_SetACL_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SetACL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetACL"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SetACL_greyware_tool_keyword = /\/SetACL\.exe/ nocase ascii wide
                        $string2_SetACL_greyware_tool_keyword = /\/SetACL64\.\.exe/ nocase ascii wide
                        $string3_SetACL_greyware_tool_keyword = /\\SetACL\.exe/ nocase ascii wide
                        $string4_SetACL_greyware_tool_keyword = /\\SetACL64\.exe/ nocase ascii wide
                        $string5_SetACL_greyware_tool_keyword = /\>SetACL\.exe\</ nocase ascii wide
                        $string6_SetACL_greyware_tool_keyword = /\>SetACL64\.\.exe\</ nocase ascii wide

    condition:
        any of them
}