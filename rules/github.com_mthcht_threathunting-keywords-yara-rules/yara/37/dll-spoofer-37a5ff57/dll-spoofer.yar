rule DLL_Spoofer
{
    meta:
        description = "Detection patterns for the tool 'DLL-Spoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLL-Spoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DLL\-Spoofer\.git/ nocase ascii wide
                        $string2 = /\\spoof\.py/ nocase ascii wide
                        $string3 = "DLL-Spoofer-main" nocase ascii wide
                        $string4 = "MitchHS/DLL-Spoofer" nocase ascii wide
                        $string5 = /spoof\.py\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}