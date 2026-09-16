rule rule_Powermad_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Powermad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powermad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Powermad_offensive_tool_keyword = /\/Powermad\.git/ nocase ascii wide
                        $string2_Powermad_offensive_tool_keyword = /\\Powermad/ nocase ascii wide
                        $string3_Powermad_offensive_tool_keyword = /Invoke\-DNSUpdate\.ps1/ nocase ascii wide
                        $string4_Powermad_offensive_tool_keyword = /powermad\.ps1/ nocase ascii wide
                        $string5_Powermad_offensive_tool_keyword = /Powermad\.psd1/ nocase ascii wide
                        $string6_Powermad_offensive_tool_keyword = /Powermad\.psm1/ nocase ascii wide
                        $string7_Powermad_offensive_tool_keyword = "Powermad-master" nocase ascii wide

    condition:
        any of them
}