rule rule_C2_Tool_Collection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2-Tool-Collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2-Tool-Collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2_Tool_Collection_offensive_tool_keyword = "/C2-Tool-Collection/" nocase ascii wide
                        $string2_C2_Tool_Collection_offensive_tool_keyword = /\/SprayAD\.exe/ nocase ascii wide
                        $string3_C2_Tool_Collection_offensive_tool_keyword = /\\SprayAD\.cna/ nocase ascii wide
                        $string4_C2_Tool_Collection_offensive_tool_keyword = /\\SprayAD\.exe/ nocase ascii wide
                        $string5_C2_Tool_Collection_offensive_tool_keyword = /Lapsdump\.cna/ nocase ascii wide
                        $string6_C2_Tool_Collection_offensive_tool_keyword = /Lapsdump\.exe/ nocase ascii wide
                        $string7_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.cna/ nocase ascii wide
                        $string8_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.exe/ nocase ascii wide
                        $string9_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.ps1/ nocase ascii wide
                        $string10_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.sln/ nocase ascii wide
                        $string11_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.vcxproj/ nocase ascii wide
                        $string12_C2_Tool_Collection_offensive_tool_keyword = /ReflectiveDll\./ nocase ascii wide
                        $string13_C2_Tool_Collection_offensive_tool_keyword = /ReflectiveDLLInjection\./ nocase ascii wide
                        $string14_C2_Tool_Collection_offensive_tool_keyword = /ReflectiveLoader\./ nocase ascii wide
                        $string15_C2_Tool_Collection_offensive_tool_keyword = /SprayAD\.exe\s/ nocase ascii wide
                        $string16_C2_Tool_Collection_offensive_tool_keyword = /TicketToHashcat\.py/ nocase ascii wide
                        $string17_C2_Tool_Collection_offensive_tool_keyword = "Lapsdump " nocase ascii wide

    condition:
        any of them
}