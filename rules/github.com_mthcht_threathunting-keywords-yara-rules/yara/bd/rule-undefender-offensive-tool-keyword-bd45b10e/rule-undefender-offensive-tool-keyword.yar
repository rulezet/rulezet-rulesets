rule rule_unDefender_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unDefender' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unDefender"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_unDefender_offensive_tool_keyword = /\sunDefender\.exe/ nocase ascii wide
                        $string2_unDefender_offensive_tool_keyword = /\/unDefender\.exe/ nocase ascii wide
                        $string3_unDefender_offensive_tool_keyword = /\/unDefender\.git/ nocase ascii wide
                        $string4_unDefender_offensive_tool_keyword = /\\unDefender\.exe/ nocase ascii wide
                        $string5_unDefender_offensive_tool_keyword = "APTortellini/unDefender" nocase ascii wide
                        $string6_unDefender_offensive_tool_keyword = /copy\s.{0,1000}\\legit\.sys\s.{0,1000}Windows\\System32\\Drivers\\.{0,1000}\.sys/ nocase ascii wide
                        $string7_unDefender_offensive_tool_keyword = /ImpersonateAndUnload\.cpp/ nocase ascii wide
                        $string8_unDefender_offensive_tool_keyword = "unDefender-master" nocase ascii wide

    condition:
        any of them
}