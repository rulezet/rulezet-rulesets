rule bittorent
{
    meta:
        description = "Detection patterns for the tool 'bittorent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bittorent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\BitTorrent\.exe/ nocase ascii wide

    condition:
        any of them
}