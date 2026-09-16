rule rule_Invoke_RDPThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-RDPThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-RDPThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_RDPThief_offensive_tool_keyword = /\sRdpThief\.dll/ nocase ascii wide
                        $string2_Invoke_RDPThief_offensive_tool_keyword = /\/Invoke\-RDPThief\.git/ nocase ascii wide
                        $string3_Invoke_RDPThief_offensive_tool_keyword = /\/RdpThief\.dll/ nocase ascii wide
                        $string4_Invoke_RDPThief_offensive_tool_keyword = /\[\+\]\sSuccessfully\sinjected\sinto\sprocess\s/ nocase ascii wide
                        $string5_Invoke_RDPThief_offensive_tool_keyword = /\\RdpThief\.dll/ nocase ascii wide
                        $string6_Invoke_RDPThief_offensive_tool_keyword = "e382edfe2f7c38cb3d6abd20c75e1ac24ddc19f921aba4b92dda3e1774e45240" nocase ascii wide
                        $string7_Invoke_RDPThief_offensive_tool_keyword = "Invoke-RDPThief " nocase ascii wide
                        $string8_Invoke_RDPThief_offensive_tool_keyword = /Invoke\-RDPThief\.ps1/ nocase ascii wide
                        $string9_Invoke_RDPThief_offensive_tool_keyword = "The-Viper-One/Invoke-RDPThief" nocase ascii wide

    condition:
        any of them
}