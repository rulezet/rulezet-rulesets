rule rule_AVDump_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AVDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AVDump"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AVDump_greyware_tool_keyword = /\\AvDump\.exe\s\-\-pid\s.{0,1000}\s\-\-exception_ptr\s0/ nocase ascii wide
                        $string2_AVDump_greyware_tool_keyword = /AvDump\.exe\s\-\-pid\s.{0,1000}\s\-\-dump_file\s.{0,1000}\.dmp/ nocase ascii wide
                        $string3_AVDump_greyware_tool_keyword = "Dumped by AvDump" nocase ascii wide

    condition:
        any of them
}