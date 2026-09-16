rule utorrent
{
    meta:
        description = "Detection patterns for the tool 'utorrent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "utorrent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\uTorrent\\/ nocase ascii wide
                        $string2 = /\\utweb\.exe/ nocase ascii wide
                        $string3 = /AppData\\Roaming\\uTorrent/ nocase ascii wide
                        $string4 = /uTorrent\s\(1\)\.exe/ nocase ascii wide
                        $string5 = /uTorrent\.exe/ nocase ascii wide
                        $string6 = /utorrent_installer\.exe/ nocase ascii wide
                        $string7 = /utweb_installer\.exe/ nocase ascii wide

    condition:
        any of them
}