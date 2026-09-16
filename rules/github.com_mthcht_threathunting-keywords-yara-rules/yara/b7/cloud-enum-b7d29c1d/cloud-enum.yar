rule cloud_enum
{
    meta:
        description = "Detection patterns for the tool 'cloud_enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloud_enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scloud_enum\.py/ nocase ascii wide
                        $string2 = /\/cloud_enum\.git/ nocase ascii wide
                        $string3 = /\/cloud_enum\.py/ nocase ascii wide
                        $string4 = /\/cloud_enum\.txt/ nocase ascii wide
                        $string5 = /\\cloud_enum\.py/ nocase ascii wide
                        $string6 = /cloud_enum\-master\.zip/ nocase ascii wide
                        $string7 = "initstring/cloud_enum" nocase ascii wide

    condition:
        any of them
}