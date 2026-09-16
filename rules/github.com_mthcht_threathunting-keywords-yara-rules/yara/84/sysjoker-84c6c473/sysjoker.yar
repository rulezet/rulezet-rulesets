rule SysJoker
{
    meta:
        description = "Detection patterns for the tool 'SysJoker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SysJoker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\:\\ProgramData\\RecoverySystem\\recoveryWindows\.zip/ nocase ascii wide
                        $string2 = /\:\\ProgramData\\SystemData\\igfxCUIService\.exe/ nocase ascii wide
                        $string3 = /\:\\ProgramData\\SystemData\\tempo1\.txt/ nocase ascii wide
                        $string4 = /\:\\ProgramData\\SystemData\\tempo2\.txt/ nocase ascii wide
                        $string5 = /C\:\\ProgramData\\SystemData\\microsoft_Windows\.dll/ nocase ascii wide
                        $string6 = /REG\sADD\s.{0,1000}igfxCUIService/ nocase ascii wide

    condition:
        any of them
}