rule rule_Ares_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ares_offensive_tool_keyword = /\s0\.0\.0\.0\:8080\s\-\-threads/ nocase ascii wide
                        $string2_Ares_offensive_tool_keyword = " http://localhost:8080 -o agent" nocase ascii wide
                        $string3_Ares_offensive_tool_keyword = /\/Ares\.git/ nocase ascii wide
                        $string4_Ares_offensive_tool_keyword = /\/ares\.py\s/ nocase ascii wide
                        $string5_Ares_offensive_tool_keyword = /ares\.py\srunserver/ nocase ascii wide
                        $string6_Ares_offensive_tool_keyword = /ares\-master\.zip/ nocase ascii wide
                        $string7_Ares_offensive_tool_keyword = /autostart\/ares\.desktop/ nocase ascii wide
                        $string8_Ares_offensive_tool_keyword = "gunicorn ares:app" nocase ascii wide
                        $string9_Ares_offensive_tool_keyword = /sqlite\:\/\/\/ares\.db/ nocase ascii wide
                        $string10_Ares_offensive_tool_keyword = "sweetsoftware/Ares" nocase ascii wide

    condition:
        any of them
}