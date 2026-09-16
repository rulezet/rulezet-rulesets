rule rule_Elevator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Elevator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Elevator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Elevator_offensive_tool_keyword = /\/Elevator\.git/ nocase ascii wide
                        $string2_Elevator_offensive_tool_keyword = /\[\!\]\sElevated\sprocess\sspawned\!/ nocase ascii wide
                        $string3_Elevator_offensive_tool_keyword = /\\elevator\.exe\s\-/ nocase ascii wide
                        $string4_Elevator_offensive_tool_keyword = /\\Elevator\\target\\release/ nocase ascii wide
                        $string5_Elevator_offensive_tool_keyword = "73415a38d4b76dd2215d9fd81015b36a025018552f7847494f908f50c62fc8d2" nocase ascii wide
                        $string6_Elevator_offensive_tool_keyword = "AAB75969-92BA-4632-9F78-AF52FA2BCE1E" nocase ascii wide
                        $string7_Elevator_offensive_tool_keyword = /elevator\.exe\s.{0,1000}cmd\.exe/ nocase ascii wide
                        $string8_Elevator_offensive_tool_keyword = "Kudaes/Elevator" nocase ascii wide

    condition:
        any of them
}