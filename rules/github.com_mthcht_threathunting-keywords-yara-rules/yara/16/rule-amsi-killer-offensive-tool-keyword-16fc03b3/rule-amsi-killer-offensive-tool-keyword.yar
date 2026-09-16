rule rule_Amsi_Killer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Amsi-Killer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amsi-Killer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Amsi_Killer_offensive_tool_keyword = /\/Amsi\-Killer\.git/ nocase ascii wide
                        $string2_Amsi_Killer_offensive_tool_keyword = "AMSI patched in all powershells" nocase ascii wide
                        $string3_Amsi_Killer_offensive_tool_keyword = /Amsi\-Killer\.exe/ nocase ascii wide
                        $string4_Amsi_Killer_offensive_tool_keyword = /Amsi\-Killer\.sln/ nocase ascii wide
                        $string5_Amsi_Killer_offensive_tool_keyword = /Amsi\-Killer\.vcxproj/ nocase ascii wide
                        $string6_Amsi_Killer_offensive_tool_keyword = "Amsi-Killer-master" nocase ascii wide
                        $string7_Amsi_Killer_offensive_tool_keyword = "E2E64E89-8ACE-4AA1-9340-8E987F5F142F" nocase ascii wide
                        $string8_Amsi_Killer_offensive_tool_keyword = "ZeroMemoryEx/Amsi-Killer" nocase ascii wide

    condition:
        any of them
}