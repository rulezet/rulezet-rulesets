rule rule_dir_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dir' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dir"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dir_greyware_tool_keyword = /\sdir\s\/s\s.{0,1000}\/\sMicrosoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string2_dir_greyware_tool_keyword = /dir\s\/a\s\/b\sc\:\\windows\\kb/ nocase ascii wide
                        $string3_dir_greyware_tool_keyword = /dir\s\/a\:h\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials\\/ nocase ascii wide
                        $string4_dir_greyware_tool_keyword = /dir\s\/a\:h\sC\:\\Users\\.{0,1000}\\AppData\\Roaming\\Microsoft\\Credentials\\/ nocase ascii wide
                        $string5_dir_greyware_tool_keyword = /dir\s\/b\s\/ad\s\\"C\:\\Users\\"/ nocase ascii wide
                        $string6_dir_greyware_tool_keyword = /dir\s\/b\/a\s\%appdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
                        $string7_dir_greyware_tool_keyword = /dir\s\/b\/a\s\%localappdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
                        $string8_dir_greyware_tool_keyword = /dir\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials/ nocase ascii wide

    condition:
        any of them
}