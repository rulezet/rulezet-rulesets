rule net
{
    meta:
        description = "Detection patterns for the tool 'net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "net"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /net\sgroup\s.{0,1000}domain\sadmins.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}