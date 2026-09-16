rule rule_Mystikal_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Mystikal' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mystikal"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Mystikal_offensive_tool_keyword = /\smystikal\.py/ nocase ascii wide
                        $string2_Mystikal_offensive_tool_keyword = /\/MacroWord_Payload\/macro\.txt/ nocase ascii wide
                        $string3_Mystikal_offensive_tool_keyword = /\/Mystikal\.git/ nocase ascii wide
                        $string4_Mystikal_offensive_tool_keyword = /\/mystikal\.py/ nocase ascii wide
                        $string5_Mystikal_offensive_tool_keyword = /\/PDF_Payload\/script\.txt/ nocase ascii wide
                        $string6_Mystikal_offensive_tool_keyword = /\\mystikal\.py/ nocase ascii wide
                        $string7_Mystikal_offensive_tool_keyword = "D00MFist/Mystikal" nocase ascii wide
                        $string8_Mystikal_offensive_tool_keyword = "Mystikal-main" nocase ascii wide
                        $string9_Mystikal_offensive_tool_keyword = /PDF_Payload.{0,1000}Doomfist\.pdf/ nocase ascii wide

    condition:
        any of them
}