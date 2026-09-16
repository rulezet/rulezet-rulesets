rule rule_SysJoker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SysJoker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SysJoker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SysJoker_offensive_tool_keyword = /\:\\ProgramData\\RecoverySystem\\recoveryWindows\.zip/ nocase ascii wide
                        $string2_SysJoker_offensive_tool_keyword = /\:\\ProgramData\\SystemData\\igfxCUIService\.exe/ nocase ascii wide
                        $string3_SysJoker_offensive_tool_keyword = /\:\\ProgramData\\SystemData\\tempo1\.txt/ nocase ascii wide
                        $string4_SysJoker_offensive_tool_keyword = /\:\\ProgramData\\SystemData\\tempo2\.txt/ nocase ascii wide
                        $string5_SysJoker_offensive_tool_keyword = /C\:\\ProgramData\\SystemData\\microsoft_Windows\.dll/ nocase ascii wide
                        $string6_SysJoker_offensive_tool_keyword = /REG\sADD\s.{0,1000}igfxCUIService/ nocase ascii wide

    condition:
        any of them
}