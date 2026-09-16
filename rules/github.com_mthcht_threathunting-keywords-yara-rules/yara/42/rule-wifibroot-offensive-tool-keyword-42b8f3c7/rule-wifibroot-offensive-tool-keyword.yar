rule rule_wifibroot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wifibroot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifibroot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wifibroot_offensive_tool_keyword = "/WiFiBroot" nocase ascii wide
                        $string2_wifibroot_offensive_tool_keyword = /\-\-mode\s3\s\-\-type\shandshake\s\-\-essid\s.{0,1000}\s\-\-verbose\s\-d\sdicts\/.{0,1000}\s\-\-read\s.{0,1000}\.cap/ nocase ascii wide
                        $string3_wifibroot_offensive_tool_keyword = /\-\-mode\s3\s\-\-type\spmkid\s\-\-verbose\s\-d\sdicts\/.{0,1000}\s\-\-read\s.{0,1000}\.txt/ nocase ascii wide
                        $string4_wifibroot_offensive_tool_keyword = /wifibroot\.py/ nocase ascii wide
                        $string5_wifibroot_offensive_tool_keyword = /wireless\/captures\.py/ nocase ascii wide
                        $string6_wifibroot_offensive_tool_keyword = /wireless\/cracker\.py/ nocase ascii wide
                        $string7_wifibroot_offensive_tool_keyword = /wireless\/pmkid\.py/ nocase ascii wide
                        $string8_wifibroot_offensive_tool_keyword = /wireless\/sniper\.py/ nocase ascii wide

    condition:
        any of them
}