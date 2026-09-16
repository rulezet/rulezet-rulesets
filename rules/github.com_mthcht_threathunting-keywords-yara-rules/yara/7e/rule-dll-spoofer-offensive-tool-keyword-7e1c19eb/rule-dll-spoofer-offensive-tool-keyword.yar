rule rule_DLL_Spoofer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DLL-Spoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLL-Spoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DLL_Spoofer_offensive_tool_keyword = /\/DLL\-Spoofer\.git/ nocase ascii wide
                        $string2_DLL_Spoofer_offensive_tool_keyword = /\\spoof\.py/ nocase ascii wide
                        $string3_DLL_Spoofer_offensive_tool_keyword = "DLL-Spoofer-main" nocase ascii wide
                        $string4_DLL_Spoofer_offensive_tool_keyword = "MitchHS/DLL-Spoofer" nocase ascii wide
                        $string5_DLL_Spoofer_offensive_tool_keyword = /spoof\.py\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}