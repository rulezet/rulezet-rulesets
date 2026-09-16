rule EvilSln
{
    meta:
        description = "Detection patterns for the tool 'EvilSln' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilSln"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EvilSln\.git/ nocase ascii wide
                        $string2 = /\/EvilSln\/.{0,1000}\.suo/ nocase ascii wide
                        $string3 = /\\EvilSln\\.{0,1000}\.suo/ nocase ascii wide
                        $string4 = "0FE0D049-F352-477D-BCCD-ACBF7D4F6F15" nocase ascii wide
                        $string5 = "cjm00n/EvilSln" nocase ascii wide
                        $string6 = "EvilSln-main" nocase ascii wide

    condition:
        any of them
}