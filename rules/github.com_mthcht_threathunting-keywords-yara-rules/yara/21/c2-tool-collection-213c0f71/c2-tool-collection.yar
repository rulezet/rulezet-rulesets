rule C2_Tool_Collection
{
    meta:
        description = "Detection patterns for the tool 'C2-Tool-Collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2-Tool-Collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/C2-Tool-Collection/" nocase ascii wide
                        $string2 = /\/SprayAD\.exe/ nocase ascii wide
                        $string3 = /\\SprayAD\.cna/ nocase ascii wide
                        $string4 = /\\SprayAD\.exe/ nocase ascii wide
                        $string5 = /Lapsdump\.cna/ nocase ascii wide
                        $string6 = /Lapsdump\.exe/ nocase ascii wide
                        $string7 = /PetitPotam\.cna/ nocase ascii wide
                        $string8 = /PetitPotam\.exe/ nocase ascii wide
                        $string9 = /PetitPotam\.ps1/ nocase ascii wide
                        $string10 = /PetitPotam\.sln/ nocase ascii wide
                        $string11 = /PetitPotam\.vcxproj/ nocase ascii wide
                        $string12 = /ReflectiveDll\./ nocase ascii wide
                        $string13 = /ReflectiveDLLInjection\./ nocase ascii wide
                        $string14 = /ReflectiveLoader\./ nocase ascii wide
                        $string15 = /SprayAD\.exe\s/ nocase ascii wide
                        $string16 = /TicketToHashcat\.py/ nocase ascii wide
                        $string17 = "Lapsdump " nocase ascii wide

    condition:
        any of them
}