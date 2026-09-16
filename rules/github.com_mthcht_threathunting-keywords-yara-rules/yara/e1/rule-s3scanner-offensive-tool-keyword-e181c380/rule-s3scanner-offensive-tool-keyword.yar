rule rule_S3Scanner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'S3Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S3Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_S3Scanner_offensive_tool_keyword = /\sdump\s\-\-bucket\s.{0,1000}\-\-dump\-dir/ nocase ascii wide
                        $string2_S3Scanner_offensive_tool_keyword = /\s\-\-threads\s.{0,1000}\sscan\s\-\-buckets\-file.{0,1000}\s/ nocase ascii wide
                        $string3_S3Scanner_offensive_tool_keyword = /\/S3Scanner\.git/ nocase ascii wide
                        $string4_S3Scanner_offensive_tool_keyword = "install s3scanner" nocase ascii wide
                        $string5_S3Scanner_offensive_tool_keyword = "python3 -m S3Scanner" nocase ascii wide
                        $string6_S3Scanner_offensive_tool_keyword = "s3scanner -" nocase ascii wide
                        $string7_S3Scanner_offensive_tool_keyword = "s3scanner dump " nocase ascii wide
                        $string8_S3Scanner_offensive_tool_keyword = "s3scanner scan " nocase ascii wide
                        $string9_S3Scanner_offensive_tool_keyword = "S3Scanner-master" nocase ascii wide
                        $string10_S3Scanner_offensive_tool_keyword = "sa7mon/S3Scanner" nocase ascii wide

    condition:
        any of them
}