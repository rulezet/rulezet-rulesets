rule rule_Universal_Virus_Sniffer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Universal Virus Sniffer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Universal Virus Sniffer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Universal_Virus_Sniffer_greyware_tool_keyword = /\/uvs_v415eng\.zip/ nocase ascii wide
                        $string2_Universal_Virus_Sniffer_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\Doc_ENG\\_Rootkit\sdetection\.txt/ nocase ascii wide
                        $string3_Universal_Virus_Sniffer_greyware_tool_keyword = /\\Update_UVS\.exe/ nocase ascii wide
                        $string4_Universal_Virus_Sniffer_greyware_tool_keyword = /\\uvs_v415eng\.zip/ nocase ascii wide
                        $string5_Universal_Virus_Sniffer_greyware_tool_keyword = "dd90d845a111bc52b3d81dd597c5eaf0ef41d2278383a668f8932d8faefccbda" nocase ascii wide
                        $string6_Universal_Virus_Sniffer_greyware_tool_keyword = /http\:\/\/dsrt\.dyndns\.org\:8888\/uvs_freeupdate_en\.htm/ nocase ascii wide
                        $string7_Universal_Virus_Sniffer_greyware_tool_keyword = /http\:\/\/dsrt\.dyndns\.org\:8888\/uvs_register_en\.htm/ nocase ascii wide
                        $string8_Universal_Virus_Sniffer_greyware_tool_keyword = /PUA\.Win32\.uVirusSniffer\.A/ nocase ascii wide
                        $string9_Universal_Virus_Sniffer_greyware_tool_keyword = "PUA:Win32/Packunwan" nocase ascii wide
                        $string10_Universal_Virus_Sniffer_greyware_tool_keyword = /Universal\.Virus\.Sniffer\.4\.15\.zip/ nocase ascii wide
                        $string11_Universal_Virus_Sniffer_greyware_tool_keyword = "Win32/UniversalVirusSniffer" nocase ascii wide

    condition:
        any of them
}