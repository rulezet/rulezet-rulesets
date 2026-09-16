rule rule_EDR_Detector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDR_Detector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDR_Detector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDR_Detector_offensive_tool_keyword = /\/EDR_Detector\.git/ nocase ascii wide
                        $string2_EDR_Detector_offensive_tool_keyword = /\/EDR_Detector\.rs/ nocase ascii wide
                        $string3_EDR_Detector_offensive_tool_keyword = /\\EDR_Detector\.rs/ nocase ascii wide
                        $string4_EDR_Detector_offensive_tool_keyword = "EDR Detector by trickster0" nocase ascii wide
                        $string5_EDR_Detector_offensive_tool_keyword = /EDR_Detection\.exe/ nocase ascii wide
                        $string6_EDR_Detector_offensive_tool_keyword = /EDR_Detector\.7z/ nocase ascii wide
                        $string7_EDR_Detector_offensive_tool_keyword = "EDR_Detector-master" nocase ascii wide
                        $string8_EDR_Detector_offensive_tool_keyword = "trickster0/EDR_Detector" nocase ascii wide

    condition:
        any of them
}