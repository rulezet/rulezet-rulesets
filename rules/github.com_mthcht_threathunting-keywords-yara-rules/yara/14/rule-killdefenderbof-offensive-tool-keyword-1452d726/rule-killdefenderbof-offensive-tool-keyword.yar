rule rule_KillDefenderBOF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KillDefenderBOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KillDefenderBOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KillDefenderBOF_offensive_tool_keyword = "/KillDefenderBOF" nocase ascii wide
                        $string2_KillDefenderBOF_offensive_tool_keyword = /\\KillDefender\.c/ nocase ascii wide
                        $string3_KillDefenderBOF_offensive_tool_keyword = /\\KillDefender\.o/ nocase ascii wide
                        $string4_KillDefenderBOF_offensive_tool_keyword = /KillDefender\.h/ nocase ascii wide
                        $string5_KillDefenderBOF_offensive_tool_keyword = "KillDefenderBOF-main" nocase ascii wide
                        $string6_KillDefenderBOF_offensive_tool_keyword = /temp.{0,1000}KillDefender/ nocase ascii wide

    condition:
        any of them
}