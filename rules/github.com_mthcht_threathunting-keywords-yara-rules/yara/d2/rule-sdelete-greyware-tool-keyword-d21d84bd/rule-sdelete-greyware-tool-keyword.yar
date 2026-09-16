rule rule_sdelete_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sdelete' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sdelete"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sdelete_greyware_tool_keyword = /\/sdelete\.exe/ nocase ascii wide
                        $string2_sdelete_greyware_tool_keyword = /\/SDelete\.zip/ nocase ascii wide
                        $string3_sdelete_greyware_tool_keyword = /\/sdelete64\.exe/ nocase ascii wide
                        $string4_sdelete_greyware_tool_keyword = /\/sdelete64a\.exe/ nocase ascii wide
                        $string5_sdelete_greyware_tool_keyword = /\\sdelete\.exe/ nocase ascii wide
                        $string6_sdelete_greyware_tool_keyword = /\\SDelete\.zip/ nocase ascii wide
                        $string7_sdelete_greyware_tool_keyword = /\\sdelete64\.exe/ nocase ascii wide
                        $string8_sdelete_greyware_tool_keyword = /\\sdelete64a\.exe/ nocase ascii wide
                        $string9_sdelete_greyware_tool_keyword = /\\Software\\Sysinternals\\Sdelete/ nocase ascii wide
                        $string10_sdelete_greyware_tool_keyword = /\>sdelete\.exe\</ nocase ascii wide
                        $string11_sdelete_greyware_tool_keyword = ">sysinternals sdelete<" nocase ascii wide

    condition:
        any of them
}