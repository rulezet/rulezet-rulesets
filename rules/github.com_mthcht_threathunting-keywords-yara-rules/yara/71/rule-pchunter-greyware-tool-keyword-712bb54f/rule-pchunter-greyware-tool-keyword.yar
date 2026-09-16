rule rule_PCHunter_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_PCHunter_greyware_tool_keyword = /\/PCHunter\.exe/ nocase ascii wide
                        $string2_PCHunter_greyware_tool_keyword = /\/PCHunter_free\.zip/ nocase ascii wide
                        $string3_PCHunter_greyware_tool_keyword = /\\AppData\\Local\\Temp\\PCHunter\.sys/ nocase ascii wide
                        $string4_PCHunter_greyware_tool_keyword = /\\ControlSet001\\Services\\PCHunter/ nocase ascii wide
                        $string5_PCHunter_greyware_tool_keyword = /\\PCHunter\.exe/ nocase ascii wide
                        $string6_PCHunter_greyware_tool_keyword = /\\PCHunter_free\.zip/ nocase ascii wide
                        $string7_PCHunter_greyware_tool_keyword = /\\PCHunter32\.pdb/ nocase ascii wide
                        $string8_PCHunter_greyware_tool_keyword = /\\PCHunter64ar\.sys/ nocase ascii wide
                        $string9_PCHunter_greyware_tool_keyword = ">Epoolsoft Windows Information View Tools<" nocase ascii wide
                        $string10_PCHunter_greyware_tool_keyword = ">PC Hunter<" nocase ascii wide
                        $string11_PCHunter_greyware_tool_keyword = /\>PCHunter\.sys\</ nocase ascii wide
                        $string12_PCHunter_greyware_tool_keyword = "648eaadf2d81af9ea6792d48740aa3ef4787303f95a0e2abaf23b87b13758eb7" nocase ascii wide
                        $string13_PCHunter_greyware_tool_keyword = /http\:\/\/www\.epoolsoft\.com\/pchunter\/pchunter_free/ nocase ascii wide
                        $string14_PCHunter_greyware_tool_keyword = /http\:\/\/www\.epoolsoft\.com\/PCHunter_Standard/ nocase ascii wide
                        $string15_PCHunter_greyware_tool_keyword = /https\:\/\/www\.majorgeeks\.com\/files\/details\/pc_hunter\.html/ nocase ascii wide
                        $string16_PCHunter_greyware_tool_keyword = "PC Hunter Standard" nocase ascii wide
                        $string17_PCHunter_greyware_tool_keyword = /PCHunter32\.exe/ nocase ascii wide
                        $string18_PCHunter_greyware_tool_keyword = /PCHunter64\.exe/ nocase ascii wide

    condition:
        any of them
}