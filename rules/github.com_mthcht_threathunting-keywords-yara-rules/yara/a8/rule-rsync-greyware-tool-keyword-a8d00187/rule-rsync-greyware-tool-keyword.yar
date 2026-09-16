rule rule_rsync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rsync_greyware_tool_keyword = /rsync\s\-r\s.{0,1000}\s.{0,1000}\@.{0,1000}\:/ nocase ascii wide
                        $string2_rsync_greyware_tool_keyword = /rsync\s\-r\s.{0,1000}\@.{0,1000}\:.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}