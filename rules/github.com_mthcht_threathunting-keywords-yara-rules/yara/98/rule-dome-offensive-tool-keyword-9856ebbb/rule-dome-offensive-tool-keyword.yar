rule rule_DOME_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DOME' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DOME"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DOME_offensive_tool_keyword = /\sdome\.py/ nocase ascii wide
                        $string2_DOME_offensive_tool_keyword = /\.\/dome\.py/
                        $string3_DOME_offensive_tool_keyword = /\/Dome\.git/ nocase ascii wide
                        $string4_DOME_offensive_tool_keyword = /dome\.py\s/ nocase ascii wide
                        $string5_DOME_offensive_tool_keyword = /\-m\s.{0,1000}\s\-d\s.{0,1000}\s\-w\s.{0,1000}\s\-\-top\-web\-ports/ nocase ascii wide
                        $string6_DOME_offensive_tool_keyword = "v4d1/Dome" nocase ascii wide
                        $string7_DOME_offensive_tool_keyword = /wordlists\/subdomains\-5000\.txt/ nocase ascii wide
                        $string8_DOME_offensive_tool_keyword = /wordlists\/top1million\.txt/ nocase ascii wide

    condition:
        any of them
}