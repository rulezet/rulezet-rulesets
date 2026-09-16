rule PCHunter
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/PCHunter\.exe/ nocase ascii wide
                        $string2 = /\/PCHunter_free\.zip/ nocase ascii wide
                        $string3 = /\\AppData\\Local\\Temp\\PCHunter\.sys/ nocase ascii wide
                        $string4 = /\\ControlSet001\\Services\\PCHunter/ nocase ascii wide
                        $string5 = /\\PCHunter\.exe/ nocase ascii wide
                        $string6 = /\\PCHunter_free\.zip/ nocase ascii wide
                        $string7 = /\\PCHunter32\.pdb/ nocase ascii wide
                        $string8 = /\\PCHunter64ar\.sys/ nocase ascii wide
                        $string9 = ">Epoolsoft Windows Information View Tools<" nocase ascii wide
                        $string10 = ">PC Hunter<" nocase ascii wide
                        $string11 = /\>PCHunter\.sys\</ nocase ascii wide
                        $string12 = "648eaadf2d81af9ea6792d48740aa3ef4787303f95a0e2abaf23b87b13758eb7" nocase ascii wide
                        $string13 = /http\:\/\/www\.epoolsoft\.com\/pchunter\/pchunter_free/ nocase ascii wide
                        $string14 = /http\:\/\/www\.epoolsoft\.com\/PCHunter_Standard/ nocase ascii wide
                        $string15 = /https\:\/\/www\.majorgeeks\.com\/files\/details\/pc_hunter\.html/ nocase ascii wide
                        $string16 = "PC Hunter Standard" nocase ascii wide
                        $string17 = /PCHunter32\.exe/ nocase ascii wide
                        $string18 = /PCHunter64\.exe/ nocase ascii wide

    condition:
        any of them
}