rule wifibroot
{
    meta:
        description = "Detection patterns for the tool 'wifibroot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifibroot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/WiFiBroot" nocase ascii wide
                        $string2 = /\-\-mode\s3\s\-\-type\shandshake\s\-\-essid\s.{0,1000}\s\-\-verbose\s\-d\sdicts\/.{0,1000}\s\-\-read\s.{0,1000}\.cap/ nocase ascii wide
                        $string3 = /\-\-mode\s3\s\-\-type\spmkid\s\-\-verbose\s\-d\sdicts\/.{0,1000}\s\-\-read\s.{0,1000}\.txt/ nocase ascii wide
                        $string4 = /wifibroot\.py/ nocase ascii wide
                        $string5 = /wireless\/captures\.py/ nocase ascii wide
                        $string6 = /wireless\/cracker\.py/ nocase ascii wide
                        $string7 = /wireless\/pmkid\.py/ nocase ascii wide
                        $string8 = /wireless\/sniper\.py/ nocase ascii wide

    condition:
        any of them
}