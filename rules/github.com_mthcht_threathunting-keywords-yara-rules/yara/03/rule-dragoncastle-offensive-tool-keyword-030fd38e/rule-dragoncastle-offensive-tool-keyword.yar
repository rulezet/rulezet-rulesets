rule rule_DragonCastle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DragonCastle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DragonCastle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DragonCastle_offensive_tool_keyword = /\sdragoncastle\.py/ nocase ascii wide
                        $string2_DragonCastle_offensive_tool_keyword = /\s\-target\-ip\s.{0,1000}\s\-remote\-dll\s.{0,1000}\.dll.{0,1000}\s\-local\-dll\s/ nocase ascii wide
                        $string3_DragonCastle_offensive_tool_keyword = /\/DragonCastle\.git/ nocase ascii wide
                        $string4_DragonCastle_offensive_tool_keyword = /\/DragonCastle\.pdb/ nocase ascii wide
                        $string5_DragonCastle_offensive_tool_keyword = /\/dragoncastle\.py/ nocase ascii wide
                        $string6_DragonCastle_offensive_tool_keyword = /\\DragonCastle\.dll/ nocase ascii wide
                        $string7_DragonCastle_offensive_tool_keyword = /\\DragonCastle\.pdb/ nocase ascii wide
                        $string8_DragonCastle_offensive_tool_keyword = /\\DragonCastle\-master\\/ nocase ascii wide
                        $string9_DragonCastle_offensive_tool_keyword = /\\kuhl_m_sekurlsa\.c/ nocase ascii wide
                        $string10_DragonCastle_offensive_tool_keyword = /\\pwned\.txt/ nocase ascii wide
                        $string11_DragonCastle_offensive_tool_keyword = "274F19EC-7CBA-4FC7-80E6-BB41C1FE6728" nocase ascii wide
                        $string12_DragonCastle_offensive_tool_keyword = "DragonCastle - @TheXC3LL" nocase ascii wide
                        $string13_DragonCastle_offensive_tool_keyword = /DragonCastle\.dll/ nocase ascii wide
                        $string14_DragonCastle_offensive_tool_keyword = /dragoncastle\.py\s\-/ nocase ascii wide
                        $string15_DragonCastle_offensive_tool_keyword = "mdsecactivebreach/DragonCastle" nocase ascii wide

    condition:
        any of them
}