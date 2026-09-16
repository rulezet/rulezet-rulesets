rule Box
{
    meta:
        description = "Detection patterns for the tool 'Box' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Box"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.realtime\.services\.box\.net/ nocase ascii wide
                        $string2 = /\/BoxDrive\.msi/ nocase ascii wide
                        $string3 = /\\\.boxcanvas\\BoxDesktop/ nocase ascii wide
                        $string4 = /\\box\.desktop\.updateservice\.exe/ nocase ascii wide
                        $string5 = /\\Box\.Updater\.Common\.dll/ nocase ascii wide
                        $string6 = /\\box\\box\.exe/ nocase ascii wide
                        $string7 = /\\Box\\ui\\BoxUI\.exe/ nocase ascii wide
                        $string8 = /\\BoxDesktop\.boxnote\\shell\\/ nocase ascii wide
                        $string9 = /\\BoxDrive\.msi/ nocase ascii wide
                        $string10 = /\\Program\sFiles\\Box\\Box\\/ nocase ascii wide
                        $string11 = /\\Root\\InventoryApplicationFile\\boxui\.exe/ nocase ascii wide
                        $string12 = /\>Box\,\sInc\.\</ nocase ascii wide
                        $string13 = /Box\.Desktop\.Installer\.CustomActions/ nocase ascii wide
                        $string14 = /cdn.{0,1000}\.boxcdn\.net/ nocase ascii wide
                        $string15 = /HKLM\\SOFTWARE\\Box\\Box/ nocase ascii wide
                        $string16 = /sanalytics\.box\.com/ nocase ascii wide
                        $string17 = /upload\.box\.com/ nocase ascii wide

    condition:
        any of them
}