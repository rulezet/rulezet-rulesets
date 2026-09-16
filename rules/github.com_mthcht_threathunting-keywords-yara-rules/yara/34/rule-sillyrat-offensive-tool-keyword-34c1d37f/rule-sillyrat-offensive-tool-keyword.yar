rule rule_SillyRAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SillyRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SillyRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SillyRAT_offensive_tool_keyword = "hash3liZer/SillyRAT" nocase ascii wide
                        $string2_SillyRAT_offensive_tool_keyword = "keylogger dump" nocase ascii wide
                        $string3_SillyRAT_offensive_tool_keyword = /server\.py\sgenerate\s\-\-address\s.{0,1000}\s\-\-port\s.{0,1000}\s\-\-output\s.{0,1000}\s\-\-source/ nocase ascii wide
                        $string4_SillyRAT_offensive_tool_keyword = /SillyRAT\.git/ nocase ascii wide
                        $string5_SillyRAT_offensive_tool_keyword = /sillyrat\.py/ nocase ascii wide

    condition:
        any of them
}