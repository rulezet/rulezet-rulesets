rule redpill
{
    meta:
        description = "Detection patterns for the tool 'redpill' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redpill"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sGet\-AVStatus\.ps1/ nocase ascii wide
                        $string2 = /\slist\-recycle\-bin\.ps1/ nocase ascii wide
                        $string3 = /\sps2exe\.ps1/ nocase ascii wide
                        $string4 = /\.ps1\s\-sysinfo\sEnum/ nocase ascii wide
                        $string5 = /\/ps2exe\.ps1/ nocase ascii wide
                        $string6 = /\/vbs2exe\.exe/ nocase ascii wide
                        $string7 = /\\credentials\.log/ nocase ascii wide
                        $string8 = /\\Get\-AVStatus\.ps1/ nocase ascii wide
                        $string9 = /\\ksjjhav\.log/ nocase ascii wide
                        $string10 = /\\list\-recycle\-bin\.ps1/ nocase ascii wide
                        $string11 = /\\OutlookEmails\.log/ nocase ascii wide
                        $string12 = /\\ps2exe\.ps1/ nocase ascii wide
                        $string13 = /\\Screenshot\.exe\s/ nocase ascii wide
                        $string14 = /\\Screenshot\.ps1/ nocase ascii wide
                        $string15 = /\\Temp\\clipboard\.log/ nocase ascii wide
                        $string16 = /\\Temp\\dave\.log/ nocase ascii wide
                        $string17 = /\\Temp\\fsdgss\.log/ nocase ascii wide
                        $string18 = /\\vbs2exe\.exe/ nocase ascii wide
                        $string19 = /BATtoEXEconverter\.bat/ nocase ascii wide
                        $string20 = /identify_offensive_tools\.ps1/ nocase ascii wide
                        $string21 = /Mitre\-T1202\.ps1/ nocase ascii wide
                        $string22 = /Temp\\iprange\.log/ nocase ascii wide
                        $string23 = /vbs2exe\.exe\s/ nocase ascii wide

    condition:
        any of them
}