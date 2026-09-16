rule rule_Box_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Box' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Box"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Box_greyware_tool_keyword = /\.realtime\.services\.box\.net/ nocase ascii wide
                        $string2_Box_greyware_tool_keyword = /\/BoxDrive\.msi/ nocase ascii wide
                        $string3_Box_greyware_tool_keyword = /\\\.boxcanvas\\BoxDesktop/ nocase ascii wide
                        $string4_Box_greyware_tool_keyword = /\\box\.desktop\.updateservice\.exe/ nocase ascii wide
                        $string5_Box_greyware_tool_keyword = /\\Box\.Updater\.Common\.dll/ nocase ascii wide
                        $string6_Box_greyware_tool_keyword = /\\box\\box\.exe/ nocase ascii wide
                        $string7_Box_greyware_tool_keyword = /\\Box\\ui\\BoxUI\.exe/ nocase ascii wide
                        $string8_Box_greyware_tool_keyword = /\\BoxDesktop\.boxnote\\shell\\/ nocase ascii wide
                        $string9_Box_greyware_tool_keyword = /\\BoxDrive\.msi/ nocase ascii wide
                        $string10_Box_greyware_tool_keyword = /\\Program\sFiles\\Box\\Box\\/ nocase ascii wide
                        $string11_Box_greyware_tool_keyword = /\\Root\\InventoryApplicationFile\\boxui\.exe/ nocase ascii wide
                        $string12_Box_greyware_tool_keyword = /\>Box\,\sInc\.\</ nocase ascii wide
                        $string13_Box_greyware_tool_keyword = /Box\.Desktop\.Installer\.CustomActions/ nocase ascii wide
                        $string14_Box_greyware_tool_keyword = /cdn.{0,1000}\.boxcdn\.net/ nocase ascii wide
                        $string15_Box_greyware_tool_keyword = /HKLM\\SOFTWARE\\Box\\Box/ nocase ascii wide
                        $string16_Box_greyware_tool_keyword = /sanalytics\.box\.com/ nocase ascii wide
                        $string17_Box_greyware_tool_keyword = /upload\.box\.com/ nocase ascii wide

    condition:
        any of them
}