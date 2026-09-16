rule rule_TokenPlayer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TokenPlayer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenPlayer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TokenPlayer_offensive_tool_keyword = /\s\-\-maketoken\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-domain\s/ nocase ascii wide
                        $string2_TokenPlayer_offensive_tool_keyword = " --spoofppid --ppid " nocase ascii wide
                        $string3_TokenPlayer_offensive_tool_keyword = /\sUAC\-TokenMagic\.ps1/ nocase ascii wide
                        $string4_TokenPlayer_offensive_tool_keyword = /\.exe\s\-\-exec\s\-\-pid\s.{0,1000}\s\-\-prog\s.{0,1000}cmd\.exe/ nocase ascii wide
                        $string5_TokenPlayer_offensive_tool_keyword = /\.exe\s\-\-impersonate\s\-\-pid\s/ nocase ascii wide
                        $string6_TokenPlayer_offensive_tool_keyword = /\/TokenPlayer\.git/ nocase ascii wide
                        $string7_TokenPlayer_offensive_tool_keyword = /\/UAC\-TokenMagic\.ps1/ nocase ascii wide
                        $string8_TokenPlayer_offensive_tool_keyword = /\[\+\]ImpersonateLoggedOnUser\(\)\ssucceed\!/ nocase ascii wide
                        $string9_TokenPlayer_offensive_tool_keyword = /\\ProcessSpoofing\.h/ nocase ascii wide
                        $string10_TokenPlayer_offensive_tool_keyword = /\\TokenPlayer\.cpp/ nocase ascii wide
                        $string11_TokenPlayer_offensive_tool_keyword = /\\TokenPlayer\.exe/ nocase ascii wide
                        $string12_TokenPlayer_offensive_tool_keyword = /\\TokenPlayer\\TokenPlayer\\/ nocase ascii wide
                        $string13_TokenPlayer_offensive_tool_keyword = /\\UAC\-TokenMagic\.ps1/ nocase ascii wide
                        $string14_TokenPlayer_offensive_tool_keyword = /\]Spawning\sProcess\swith\sSpoofed\sParent/ nocase ascii wide
                        $string15_TokenPlayer_offensive_tool_keyword = "0ADFD1F0-7C15-4A22-87B4-F67E046ECD96" nocase ascii wide
                        $string16_TokenPlayer_offensive_tool_keyword = "95d19ae58bbd6b38b4988fae5c7b514c8451a15e940f1392bcf1f93374364054" nocase ascii wide
                        $string17_TokenPlayer_offensive_tool_keyword = "S1ckB0y1337/TokenPlayer" nocase ascii wide
                        $string18_TokenPlayer_offensive_tool_keyword = /TokenPlayer\-v0\.3\.exe/ nocase ascii wide
                        $string19_TokenPlayer_offensive_tool_keyword = /TokenPlayer\-v0\.4\.exe/ nocase ascii wide
                        $string20_TokenPlayer_offensive_tool_keyword = /TokenPlayer\-v0\.5\.exe/ nocase ascii wide
                        $string21_TokenPlayer_offensive_tool_keyword = /TokenPlayer\-v0\.6\.exe/ nocase ascii wide
                        $string22_TokenPlayer_offensive_tool_keyword = /TokenPlayer\-v0\.7\.exe/ nocase ascii wide
                        $string23_TokenPlayer_offensive_tool_keyword = /TokenPlayer\-v0\.8\.exe/ nocase ascii wide

    condition:
        any of them
}