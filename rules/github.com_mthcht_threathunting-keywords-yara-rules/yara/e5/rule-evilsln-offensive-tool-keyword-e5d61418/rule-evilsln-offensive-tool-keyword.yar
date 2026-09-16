rule rule_EvilSln_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EvilSln' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilSln"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EvilSln_offensive_tool_keyword = /\/EvilSln\.git/ nocase ascii wide
                        $string2_EvilSln_offensive_tool_keyword = /\/EvilSln\/.{0,1000}\.suo/ nocase ascii wide
                        $string3_EvilSln_offensive_tool_keyword = /\\EvilSln\\.{0,1000}\.suo/ nocase ascii wide
                        $string4_EvilSln_offensive_tool_keyword = "0FE0D049-F352-477D-BCCD-ACBF7D4F6F15" nocase ascii wide
                        $string5_EvilSln_offensive_tool_keyword = "cjm00n/EvilSln" nocase ascii wide
                        $string6_EvilSln_offensive_tool_keyword = "EvilSln-main" nocase ascii wide

    condition:
        any of them
}