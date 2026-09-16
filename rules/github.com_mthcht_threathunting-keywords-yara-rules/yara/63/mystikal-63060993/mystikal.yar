rule Mystikal
{
    meta:
        description = "Detection patterns for the tool 'Mystikal' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mystikal"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\smystikal\.py/ nocase ascii wide
                        $string2 = /\/MacroWord_Payload\/macro\.txt/ nocase ascii wide
                        $string3 = /\/Mystikal\.git/ nocase ascii wide
                        $string4 = /\/mystikal\.py/ nocase ascii wide
                        $string5 = /\/PDF_Payload\/script\.txt/ nocase ascii wide
                        $string6 = /\\mystikal\.py/ nocase ascii wide
                        $string7 = "D00MFist/Mystikal" nocase ascii wide
                        $string8 = "Mystikal-main" nocase ascii wide
                        $string9 = /PDF_Payload.{0,1000}Doomfist\.pdf/ nocase ascii wide

    condition:
        any of them
}