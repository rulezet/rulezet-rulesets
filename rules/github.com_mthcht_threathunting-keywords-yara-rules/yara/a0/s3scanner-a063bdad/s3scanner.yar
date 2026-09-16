rule S3Scanner
{
    meta:
        description = "Detection patterns for the tool 'S3Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S3Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdump\s\-\-bucket\s.{0,1000}\-\-dump\-dir/ nocase ascii wide
                        $string2 = /\s\-\-threads\s.{0,1000}\sscan\s\-\-buckets\-file.{0,1000}\s/ nocase ascii wide
                        $string3 = /\/S3Scanner\.git/ nocase ascii wide
                        $string4 = "install s3scanner" nocase ascii wide
                        $string5 = "python3 -m S3Scanner" nocase ascii wide
                        $string6 = "s3scanner -" nocase ascii wide
                        $string7 = "s3scanner dump " nocase ascii wide
                        $string8 = "s3scanner scan " nocase ascii wide
                        $string9 = "S3Scanner-master" nocase ascii wide
                        $string10 = "sa7mon/S3Scanner" nocase ascii wide

    condition:
        any of them
}