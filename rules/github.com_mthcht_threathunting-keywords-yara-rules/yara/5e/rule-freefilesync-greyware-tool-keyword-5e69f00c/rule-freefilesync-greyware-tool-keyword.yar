rule rule_freefilesync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'freefilesync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "freefilesync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_freefilesync_greyware_tool_keyword = /\/FreeFileSync\.exe/ nocase ascii wide
                        $string2_freefilesync_greyware_tool_keyword = /\/FreeFileSync\.tar\.gz/ nocase ascii wide
                        $string3_freefilesync_greyware_tool_keyword = /\/FreeFileSync_.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string4_freefilesync_greyware_tool_keyword = /\/FreeFileSync_.{0,1000}_Windows_Setup\.exe/ nocase ascii wide
                        $string5_freefilesync_greyware_tool_keyword = /\/FreeFileSync_x64\.exe/ nocase ascii wide
                        $string6_freefilesync_greyware_tool_keyword = /\/FreeFileSyncPortable_.{0,1000}\.exe/ nocase ascii wide
                        $string7_freefilesync_greyware_tool_keyword = /\/RealTimeSync\.exe/ nocase ascii wide
                        $string8_freefilesync_greyware_tool_keyword = "/tmp/FreeFileSync"
                        $string9_freefilesync_greyware_tool_keyword = /\\AppData\\Roaming\\FreeFileSync\\Logs\\/ nocase ascii wide
                        $string10_freefilesync_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\FreeFileSync_is1/ nocase ascii wide
                        $string11_freefilesync_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\FreeFileSync_is1/ nocase ascii wide
                        $string12_freefilesync_greyware_tool_keyword = /\\FreeFileSync\.exe/ nocase ascii wide
                        $string13_freefilesync_greyware_tool_keyword = /\\FreeFileSync\\Logs\\/ nocase ascii wide
                        $string14_freefilesync_greyware_tool_keyword = /\\FreeFileSync_.{0,1000}_Windows_Setup\.exe/ nocase ascii wide
                        $string15_freefilesync_greyware_tool_keyword = /\\FreeFileSync_x64\.exe/ nocase ascii wide
                        $string16_freefilesync_greyware_tool_keyword = /\\FreeFileSyncPortable_.{0,1000}\.exe/ nocase ascii wide
                        $string17_freefilesync_greyware_tool_keyword = /\\Program\sFiles\\FreeFileSync/ nocase ascii wide
                        $string18_freefilesync_greyware_tool_keyword = /\\RealTimeSync\.exe/ nocase ascii wide
                        $string19_freefilesync_greyware_tool_keyword = /\\WOW6432Node\\FreeFileSync/ nocase ascii wide
                        $string20_freefilesync_greyware_tool_keyword = ">FreeFileSync - Folder Comparison and Synchronization<" nocase ascii wide
                        $string21_freefilesync_greyware_tool_keyword = ">FreeFileSync Setup<" nocase ascii wide
                        $string22_freefilesync_greyware_tool_keyword = ">FreeFileSync<" nocase ascii wide
                        $string23_freefilesync_greyware_tool_keyword = "0b0977a047ea3397c83d19f0edeef003c98021a2f64b03503f67a7189aeab4bf" nocase ascii wide
                        $string24_freefilesync_greyware_tool_keyword = "13b6443f4e1f03bc7c37fe9d260435886ad80ee292c0a3b5b9cdeb763576e31b" nocase ascii wide
                        $string25_freefilesync_greyware_tool_keyword = /api\.freefilesync\.org/ nocase ascii wide
                        $string26_freefilesync_greyware_tool_keyword = "c888fa7aadb304362df7bcb43164b6a07222739f5d2a90bf475817aa0e75013d" nocase ascii wide
                        $string27_freefilesync_greyware_tool_keyword = /\-Command\sAdd\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Program\sFiles\\FreeFileSync\\Bin\\/ nocase ascii wide
                        $string28_freefilesync_greyware_tool_keyword = "fb4d282f8d202006d682eef84a83757376c20929f62626e288a159d730fde3c9" nocase ascii wide
                        $string29_freefilesync_greyware_tool_keyword = /https\:\/\/api\.freefilesync\.org\/new_installation/ nocase ascii wide
                        $string30_freefilesync_greyware_tool_keyword = /https\:\/\/freefilesync\.org\/donate/ nocase ascii wide
                        $string31_freefilesync_greyware_tool_keyword = "pkill FreeFileSync" nocase ascii wide
                        $string32_freefilesync_greyware_tool_keyword = "pkill RealTimeSync" nocase ascii wide
                        $string33_freefilesync_greyware_tool_keyword = /SOFTWARE\\WOW6432Node\\FreeFileSync/ nocase ascii wide

    condition:
        any of them
}