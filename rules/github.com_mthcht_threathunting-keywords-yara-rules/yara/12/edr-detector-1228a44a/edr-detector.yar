rule EDR_Detector
{
    meta:
        description = "Detection patterns for the tool 'EDR_Detector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDR_Detector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EDR_Detector\.git/ nocase ascii wide
                        $string2 = /\/EDR_Detector\.rs/ nocase ascii wide
                        $string3 = /\\EDR_Detector\.rs/ nocase ascii wide
                        $string4 = "EDR Detector by trickster0" nocase ascii wide
                        $string5 = /EDR_Detection\.exe/ nocase ascii wide
                        $string6 = /EDR_Detector\.7z/ nocase ascii wide
                        $string7 = "EDR_Detector-master" nocase ascii wide
                        $string8 = "trickster0/EDR_Detector" nocase ascii wide

    condition:
        any of them
}