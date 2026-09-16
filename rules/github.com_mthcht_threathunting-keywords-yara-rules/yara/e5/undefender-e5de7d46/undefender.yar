rule unDefender
{
    meta:
        description = "Detection patterns for the tool 'unDefender' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unDefender"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sunDefender\.exe/ nocase ascii wide
                        $string2 = /\/unDefender\.exe/ nocase ascii wide
                        $string3 = /\/unDefender\.git/ nocase ascii wide
                        $string4 = /\\unDefender\.exe/ nocase ascii wide
                        $string5 = "APTortellini/unDefender" nocase ascii wide
                        $string6 = /copy\s.{0,1000}\\legit\.sys\s.{0,1000}Windows\\System32\\Drivers\\.{0,1000}\.sys/ nocase ascii wide
                        $string7 = /ImpersonateAndUnload\.cpp/ nocase ascii wide
                        $string8 = "unDefender-master" nocase ascii wide

    condition:
        any of them
}