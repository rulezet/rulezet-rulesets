rule bropper
{
    meta:
        description = "Detection patterns for the tool 'bropper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bropper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbropper\.py/ nocase ascii wide
                        $string2 = /\s\-t\s127\.0\.0\.1\s\-p\s1337\s/ nocase ascii wide
                        $string3 = /\.py\s.{0,1000}\s\-\-brop\s/ nocase ascii wide
                        $string4 = /\/Bropper\.git/ nocase ascii wide
                        $string5 = /\/bropper\.py/ nocase ascii wide
                        $string6 = /bropper\.py\s/ nocase ascii wide
                        $string7 = /Bropper\-main\.zip/ nocase ascii wide
                        $string8 = "--expected Bad --expected-stop Welcome" nocase ascii wide
                        $string9 = "Hakumarachi/Bropper" nocase ascii wide

    condition:
        any of them
}