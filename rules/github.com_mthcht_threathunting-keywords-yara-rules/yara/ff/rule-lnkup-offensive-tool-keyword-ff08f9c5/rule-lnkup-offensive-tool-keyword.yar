rule rule_LNKUp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LNKUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LNKUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LNKUp_offensive_tool_keyword = /\.py\s\-\-host\s.{0,1000}\s\-\-type\sntlm\s\-\-output\s.{0,1000}\.lnk/ nocase ascii wide
                        $string2_LNKUp_offensive_tool_keyword = /\/LNKUp\.git/ nocase ascii wide
                        $string3_LNKUp_offensive_tool_keyword = /\/LNKUp\/generate\.py/ nocase ascii wide
                        $string4_LNKUp_offensive_tool_keyword = /\\LNKUp\\generate\.py/ nocase ascii wide
                        $string5_LNKUp_offensive_tool_keyword = /lnkup\.py\s\-\-/ nocase ascii wide
                        $string6_LNKUp_offensive_tool_keyword = "Plazmaz/LNKUp" nocase ascii wide

    condition:
        any of them
}