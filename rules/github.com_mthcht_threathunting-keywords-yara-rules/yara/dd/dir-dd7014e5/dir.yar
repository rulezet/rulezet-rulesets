rule dir
{
    meta:
        description = "Detection patterns for the tool 'dir' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dir"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sdir\s\/s\s.{0,1000}\/\sMicrosoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
                        $string2 = /dir\s\/a\s\/b\sc\:\\windows\\kb/ nocase ascii wide
                        $string3 = /dir\s\/a\:h\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials\\/ nocase ascii wide
                        $string4 = /dir\s\/a\:h\sC\:\\Users\\.{0,1000}\\AppData\\Roaming\\Microsoft\\Credentials\\/ nocase ascii wide
                        $string5 = /dir\s\/b\s\/ad\s\\"C\:\\Users\\"/ nocase ascii wide
                        $string6 = /dir\s\/b\/a\s\%appdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
                        $string7 = /dir\s\/b\/a\s\%localappdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
                        $string8 = /dir\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials/ nocase ascii wide

    condition:
        any of them
}