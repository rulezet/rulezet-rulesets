rule SillyRAT
{
    meta:
        description = "Detection patterns for the tool 'SillyRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SillyRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "hash3liZer/SillyRAT" nocase ascii wide
                        $string2 = "keylogger dump" nocase ascii wide
                        $string3 = /server\.py\sgenerate\s\-\-address\s.{0,1000}\s\-\-port\s.{0,1000}\s\-\-output\s.{0,1000}\s\-\-source/ nocase ascii wide
                        $string4 = /SillyRAT\.git/ nocase ascii wide
                        $string5 = /sillyrat\.py/ nocase ascii wide

    condition:
        any of them
}