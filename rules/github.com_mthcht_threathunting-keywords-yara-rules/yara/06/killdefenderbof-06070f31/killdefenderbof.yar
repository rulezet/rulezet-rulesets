rule KillDefenderBOF
{
    meta:
        description = "Detection patterns for the tool 'KillDefenderBOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KillDefenderBOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/KillDefenderBOF" nocase ascii wide
                        $string2 = /\\KillDefender\.c/ nocase ascii wide
                        $string3 = /\\KillDefender\.o/ nocase ascii wide
                        $string4 = /KillDefender\.h/ nocase ascii wide
                        $string5 = "KillDefenderBOF-main" nocase ascii wide
                        $string6 = /temp.{0,1000}KillDefender/ nocase ascii wide

    condition:
        any of them
}