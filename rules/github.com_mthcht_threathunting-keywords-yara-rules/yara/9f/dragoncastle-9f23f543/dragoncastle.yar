rule DragonCastle
{
    meta:
        description = "Detection patterns for the tool 'DragonCastle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DragonCastle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdragoncastle\.py/ nocase ascii wide
                        $string2 = /\s\-target\-ip\s.{0,1000}\s\-remote\-dll\s.{0,1000}\.dll.{0,1000}\s\-local\-dll\s/ nocase ascii wide
                        $string3 = /\/DragonCastle\.git/ nocase ascii wide
                        $string4 = /\/DragonCastle\.pdb/ nocase ascii wide
                        $string5 = /\/dragoncastle\.py/ nocase ascii wide
                        $string6 = /\\DragonCastle\.dll/ nocase ascii wide
                        $string7 = /\\DragonCastle\.pdb/ nocase ascii wide
                        $string8 = /\\DragonCastle\-master\\/ nocase ascii wide
                        $string9 = /\\kuhl_m_sekurlsa\.c/ nocase ascii wide
                        $string10 = /\\pwned\.txt/ nocase ascii wide
                        $string11 = "274F19EC-7CBA-4FC7-80E6-BB41C1FE6728" nocase ascii wide
                        $string12 = "DragonCastle - @TheXC3LL" nocase ascii wide
                        $string13 = /DragonCastle\.dll/ nocase ascii wide
                        $string14 = /dragoncastle\.py\s\-/ nocase ascii wide
                        $string15 = "mdsecactivebreach/DragonCastle" nocase ascii wide

    condition:
        any of them
}