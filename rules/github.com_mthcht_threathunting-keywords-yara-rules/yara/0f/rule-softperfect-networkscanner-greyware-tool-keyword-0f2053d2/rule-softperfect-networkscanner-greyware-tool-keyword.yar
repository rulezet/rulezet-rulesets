rule rule_softperfect_networkscanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_softperfect_networkscanner_greyware_tool_keyword = /\s\/config\:netscan\.xml\s/ nocase ascii wide
                        $string2_softperfect_networkscanner_greyware_tool_keyword = /\snetscan\.exe\s/ nocase ascii wide
                        $string3_softperfect_networkscanner_greyware_tool_keyword = /\snetscan64\.exe\s/ nocase ascii wide
                        $string4_softperfect_networkscanner_greyware_tool_keyword = /\.exe\s.{0,1000}\s\/hide\s.{0,1000}\s\/range\:.{0,1000}\s\/auto\:.{0,1000}\./ nocase ascii wide
                        $string5_softperfect_networkscanner_greyware_tool_keyword = /\.exe\s\/hide\s\/range\:all/ nocase ascii wide
                        $string6_softperfect_networkscanner_greyware_tool_keyword = /\.exe\s\/wakeall/ nocase ascii wide
                        $string7_softperfect_networkscanner_greyware_tool_keyword = /\/netscan\.exe/ nocase ascii wide
                        $string8_softperfect_networkscanner_greyware_tool_keyword = /\/netscan_linux\.tar\.gz/
                        $string9_softperfect_networkscanner_greyware_tool_keyword = /\/netscan_macos\.dmg/ nocase ascii wide
                        $string10_softperfect_networkscanner_greyware_tool_keyword = /\/netscan_setup\.exe/ nocase ascii wide
                        $string11_softperfect_networkscanner_greyware_tool_keyword = /\/netscan64\.exe/ nocase ascii wide
                        $string12_softperfect_networkscanner_greyware_tool_keyword = /\\AppData\\Roaming\\SoftPerfect\sNetwork\sScanner/ nocase ascii wide
                        $string13_softperfect_networkscanner_greyware_tool_keyword = /\\netscan\.dbm\-journal/ nocase ascii wide
                        $string14_softperfect_networkscanner_greyware_tool_keyword = /\\netscan\.exe/ nocase ascii wide
                        $string15_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_linux\.tar\.gz/ nocase ascii wide
                        $string16_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_portable\.zip/ nocase ascii wide
                        $string17_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_portable\\/ nocase ascii wide
                        $string18_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_setup\.exe/ nocase ascii wide
                        $string19_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_setup\.tmp/ nocase ascii wide
                        $string20_softperfect_networkscanner_greyware_tool_keyword = /\\netscan64\.exe/ nocase ascii wide
                        $string21_softperfect_networkscanner_greyware_tool_keyword = /\\SoftPerfect\sNetwork\sScanner\\/ nocase ascii wide
                        $string22_softperfect_networkscanner_greyware_tool_keyword = /\<Data\sName\=\\"RelativeTargetName\\"\>delete\.me\</ nocase ascii wide
                        $string23_softperfect_networkscanner_greyware_tool_keyword = ">SoftPerfect Network Scanner<" nocase ascii wide
                        $string24_softperfect_networkscanner_greyware_tool_keyword = "87e8486846df3005c1b481b1c5205f661b715addfda262f56d2a41892126b399" nocase ascii wide
                        $string25_softperfect_networkscanner_greyware_tool_keyword = /https\:\/\/www\.softperfect\.com\/download\/files\/netscan/ nocase ascii wide
                        $string26_softperfect_networkscanner_greyware_tool_keyword = /https\:\/\/www\.softperfect\.com\/products\/networkscanner\/\?from\=nver/ nocase ascii wide
                        $string27_softperfect_networkscanner_greyware_tool_keyword = /netscan\.exe\s\// nocase ascii wide
                        $string28_softperfect_networkscanner_greyware_tool_keyword = /netscan_portable\.zip/ nocase ascii wide
                        $string29_softperfect_networkscanner_greyware_tool_keyword = /SoftPerfect_.{0,1000}Patch_Keygen_v2.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}