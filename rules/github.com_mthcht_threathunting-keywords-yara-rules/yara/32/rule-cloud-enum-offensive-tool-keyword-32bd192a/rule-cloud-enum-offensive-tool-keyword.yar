rule rule_cloud_enum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cloud_enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloud_enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cloud_enum_offensive_tool_keyword = /\scloud_enum\.py/ nocase ascii wide
                        $string2_cloud_enum_offensive_tool_keyword = /\/cloud_enum\.git/ nocase ascii wide
                        $string3_cloud_enum_offensive_tool_keyword = /\/cloud_enum\.py/ nocase ascii wide
                        $string4_cloud_enum_offensive_tool_keyword = /\/cloud_enum\.txt/ nocase ascii wide
                        $string5_cloud_enum_offensive_tool_keyword = /\\cloud_enum\.py/ nocase ascii wide
                        $string6_cloud_enum_offensive_tool_keyword = /cloud_enum\-master\.zip/ nocase ascii wide
                        $string7_cloud_enum_offensive_tool_keyword = "initstring/cloud_enum" nocase ascii wide

    condition:
        any of them
}