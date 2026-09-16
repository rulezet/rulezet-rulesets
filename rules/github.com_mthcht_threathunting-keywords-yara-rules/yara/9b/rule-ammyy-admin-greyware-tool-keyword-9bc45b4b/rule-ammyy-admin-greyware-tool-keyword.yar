rule rule_Ammyy_Admin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Ammyy_Admin_greyware_tool_keyword = /\\aa_nts\.dll/ nocase ascii wide
                        $string2_Ammyy_Admin_greyware_tool_keyword = /\\AA_v3\.exe/ nocase ascii wide
                        $string3_Ammyy_Admin_greyware_tool_keyword = /\\AA_v3\.log/ nocase ascii wide
                        $string4_Ammyy_Admin_greyware_tool_keyword = /\\AMMYY\\access\.log/ nocase ascii wide
                        $string5_Ammyy_Admin_greyware_tool_keyword = /\\ControlSet001\\Control\\SafeBoot\\Network\\AmmyyAdmin_/ nocase ascii wide
                        $string6_Ammyy_Admin_greyware_tool_keyword = /\\ProgramData\\AMMYY\\/ nocase ascii wide
                        $string7_Ammyy_Admin_greyware_tool_keyword = /\\SOFTWARE\\Ammyy\\Admin/ nocase ascii wide
                        $string8_Ammyy_Admin_greyware_tool_keyword = /AA_v3\.exe.{0,1000}\s\-elevated/ nocase ascii wide
                        $string9_Ammyy_Admin_greyware_tool_keyword = /AA_v3\.exe.{0,1000}\s\-service\s\-lunch/ nocase ascii wide
                        $string10_Ammyy_Admin_greyware_tool_keyword = "Ammyy Admin" nocase ascii wide
                        $string11_Ammyy_Admin_greyware_tool_keyword = "Ammyy LLC" nocase ascii wide
                        $string12_Ammyy_Admin_greyware_tool_keyword = /AMMYY_Admin\.exe/ nocase ascii wide
                        $string13_Ammyy_Admin_greyware_tool_keyword = /rl\.ammyy\.com\// nocase ascii wide
                        $string14_Ammyy_Admin_greyware_tool_keyword = /SPR\/Ammyy\.R/ nocase ascii wide
                        $string15_Ammyy_Admin_greyware_tool_keyword = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide
                        $string16_Ammyy_Admin_greyware_tool_keyword = /www\.ammyy\.com\/files\/v/ nocase ascii wide

    condition:
        any of them
}