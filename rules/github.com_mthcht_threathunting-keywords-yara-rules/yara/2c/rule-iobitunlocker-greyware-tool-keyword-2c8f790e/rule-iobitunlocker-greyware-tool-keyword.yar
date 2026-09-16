rule rule_IObitUnlocker_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IObitUnlocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IObitUnlocker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_IObitUnlocker_greyware_tool_keyword = /\sIObitUnlocker\.exe/ nocase ascii wide
                        $string2_IObitUnlocker_greyware_tool_keyword = /\/IObitUnlocker\.exe/ nocase ascii wide
                        $string3_IObitUnlocker_greyware_tool_keyword = /\/unlocker\-setup\.exe/ nocase ascii wide
                        $string4_IObitUnlocker_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\IObitUnlockerSetup/ nocase ascii wide
                        $string5_IObitUnlocker_greyware_tool_keyword = /\\Application\sData\\IObit\\IObit\sUnlocker/ nocase ascii wide
                        $string6_IObitUnlocker_greyware_tool_keyword = /\\Downloads\\IObitUnlockerSetup/ nocase ascii wide
                        $string7_IObitUnlocker_greyware_tool_keyword = /\\IObit\sUnlocker\.lnk/ nocase ascii wide
                        $string8_IObitUnlocker_greyware_tool_keyword = /\\IObitUnlocker\.dll/ nocase ascii wide
                        $string9_IObitUnlocker_greyware_tool_keyword = /\\IObitUnlocker\.exe/ nocase ascii wide
                        $string10_IObitUnlocker_greyware_tool_keyword = /\\IObitUnlocker\.ini/ nocase ascii wide
                        $string11_IObitUnlocker_greyware_tool_keyword = /\\IObitUnlocker\.log/ nocase ascii wide
                        $string12_IObitUnlocker_greyware_tool_keyword = /\\IObitUnlockerExtension\.dll/ nocase ascii wide
                        $string13_IObitUnlocker_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\IObit\\IObit\sUnlocker/ nocase ascii wide
                        $string14_IObitUnlocker_greyware_tool_keyword = /\\Program\sFiles\\IObit\\IObit\sUnlocker/ nocase ascii wide
                        $string15_IObitUnlocker_greyware_tool_keyword = /\\Uninstall\sIObit\sUnlocker\.lnk/ nocase ascii wide
                        $string16_IObitUnlocker_greyware_tool_keyword = /\\Uninstall\sIObit\sUnlocker\.url/ nocase ascii wide
                        $string17_IObitUnlocker_greyware_tool_keyword = /\\Unlocker\.exe/ nocase ascii wide
                        $string18_IObitUnlocker_greyware_tool_keyword = /\\unlocker\-setup\s\(1\)\.exe/ nocase ascii wide
                        $string19_IObitUnlocker_greyware_tool_keyword = /\\unlocker\-setup\.exe/ nocase ascii wide
                        $string20_IObitUnlocker_greyware_tool_keyword = /\\unlocker\-setup\.tmp/ nocase ascii wide
                        $string21_IObitUnlocker_greyware_tool_keyword = "2efdffd1cf3adab21ff760f009d8893d8c4cbcf63b2c3bfcc1139457c9cd430b" nocase ascii wide
                        $string22_IObitUnlocker_greyware_tool_keyword = /http\:\/\/update\.iobit\.com\/infofiles\/iobitunlocker\.upt/ nocase ascii wide
                        $string23_IObitUnlocker_greyware_tool_keyword = /https\:\/\/silentbreaksecurity\.com\/adaptive\-dll\-hijacking/ nocase ascii wide
                        $string24_IObitUnlocker_greyware_tool_keyword = /IObitUnlocker\.sys/ nocase ascii wide

    condition:
        any of them
}