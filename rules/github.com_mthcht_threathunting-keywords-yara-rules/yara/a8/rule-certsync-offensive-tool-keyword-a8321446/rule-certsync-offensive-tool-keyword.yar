rule rule_certsync_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'certsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certsync"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_certsync_offensive_tool_keyword = /\/certsync\.git/ nocase ascii wide
                        $string2_certsync_offensive_tool_keyword = /\\certipy\.pfx/ nocase ascii wide
                        $string3_certsync_offensive_tool_keyword = /\\Windows\\Tasks\\Certipy/ nocase ascii wide
                        $string4_certsync_offensive_tool_keyword = /certsync\s.{0,1000}\-\-dc\-ip/ nocase ascii wide
                        $string5_certsync_offensive_tool_keyword = "certsync -u " nocase ascii wide
                        $string6_certsync_offensive_tool_keyword = /certsync\-master\.zip/ nocase ascii wide
                        $string7_certsync_offensive_tool_keyword = "install certsync" nocase ascii wide
                        $string8_certsync_offensive_tool_keyword = "zblurx/certsync" nocase ascii wide

    condition:
        any of them
}