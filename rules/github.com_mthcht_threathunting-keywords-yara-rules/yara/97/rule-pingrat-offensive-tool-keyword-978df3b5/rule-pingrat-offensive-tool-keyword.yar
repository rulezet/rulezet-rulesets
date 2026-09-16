rule rule_PingRAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PingRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PingRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PingRAT_offensive_tool_keyword = /\/PingRAT\.git/ nocase ascii wide
                        $string2_PingRAT_offensive_tool_keyword = /\[\+\]\sICMP\slistener\sstarted\!/ nocase ascii wide
                        $string3_PingRAT_offensive_tool_keyword = /\\PingRAT\\/ nocase ascii wide
                        $string4_PingRAT_offensive_tool_keyword = /PingRAT\.exe/ nocase ascii wide
                        $string5_PingRAT_offensive_tool_keyword = "umutcamliyurt/PingRAT" nocase ascii wide

    condition:
        any of them
}