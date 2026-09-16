rule rule_utorrent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'utorrent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "utorrent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_utorrent_greyware_tool_keyword = /\\uTorrent\\/ nocase ascii wide
                        $string2_utorrent_greyware_tool_keyword = /\\utweb\.exe/ nocase ascii wide
                        $string3_utorrent_greyware_tool_keyword = /AppData\\Roaming\\uTorrent/ nocase ascii wide
                        $string4_utorrent_greyware_tool_keyword = /uTorrent\s\(1\)\.exe/ nocase ascii wide
                        $string5_utorrent_greyware_tool_keyword = /uTorrent\.exe/ nocase ascii wide
                        $string6_utorrent_greyware_tool_keyword = /utorrent_installer\.exe/ nocase ascii wide
                        $string7_utorrent_greyware_tool_keyword = /utweb_installer\.exe/ nocase ascii wide

    condition:
        any of them
}