rule IObitUnlocker
{
    meta:
        description = "Detection patterns for the tool 'IObitUnlocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IObitUnlocker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sIObitUnlocker\.exe/ nocase ascii wide
                        $string2 = /\/IObitUnlocker\.exe/ nocase ascii wide
                        $string3 = /\/unlocker\-setup\.exe/ nocase ascii wide
                        $string4 = /\\AppData\\Local\\Temp\\.{0,1000}\\IObitUnlockerSetup/ nocase ascii wide
                        $string5 = /\\Application\sData\\IObit\\IObit\sUnlocker/ nocase ascii wide
                        $string6 = /\\Downloads\\IObitUnlockerSetup/ nocase ascii wide
                        $string7 = /\\IObit\sUnlocker\.lnk/ nocase ascii wide
                        $string8 = /\\IObitUnlocker\.dll/ nocase ascii wide
                        $string9 = /\\IObitUnlocker\.exe/ nocase ascii wide
                        $string10 = /\\IObitUnlocker\.ini/ nocase ascii wide
                        $string11 = /\\IObitUnlocker\.log/ nocase ascii wide
                        $string12 = /\\IObitUnlockerExtension\.dll/ nocase ascii wide
                        $string13 = /\\Program\sFiles\s\(x86\)\\IObit\\IObit\sUnlocker/ nocase ascii wide
                        $string14 = /\\Program\sFiles\\IObit\\IObit\sUnlocker/ nocase ascii wide
                        $string15 = /\\Uninstall\sIObit\sUnlocker\.lnk/ nocase ascii wide
                        $string16 = /\\Uninstall\sIObit\sUnlocker\.url/ nocase ascii wide
                        $string17 = /\\Unlocker\.exe/ nocase ascii wide
                        $string18 = /\\unlocker\-setup\s\(1\)\.exe/ nocase ascii wide
                        $string19 = /\\unlocker\-setup\.exe/ nocase ascii wide
                        $string20 = /\\unlocker\-setup\.tmp/ nocase ascii wide
                        $string21 = "2efdffd1cf3adab21ff760f009d8893d8c4cbcf63b2c3bfcc1139457c9cd430b" nocase ascii wide
                        $string22 = /http\:\/\/update\.iobit\.com\/infofiles\/iobitunlocker\.upt/ nocase ascii wide
                        $string23 = /https\:\/\/silentbreaksecurity\.com\/adaptive\-dll\-hijacking/ nocase ascii wide
                        $string24 = /IObitUnlocker\.sys/ nocase ascii wide

    condition:
        any of them
}