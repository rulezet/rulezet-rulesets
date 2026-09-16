rule rule_track_adform_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'track.adform.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "track.adform.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_track_adform_net_greyware_tool_keyword = /https\:\/\/track\.adform\.net\/C\/\?bn\=.{0,1000}\;cpdir\=http/ nocase ascii wide

    condition:
        any of them
}