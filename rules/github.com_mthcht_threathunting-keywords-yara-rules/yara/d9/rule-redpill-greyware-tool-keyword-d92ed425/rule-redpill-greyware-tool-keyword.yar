rule rule_redpill_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'redpill' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redpill"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_redpill_greyware_tool_keyword = /\sGet\-AVStatus\.ps1/ nocase ascii wide
                        $string2_redpill_greyware_tool_keyword = /\slist\-recycle\-bin\.ps1/ nocase ascii wide
                        $string3_redpill_greyware_tool_keyword = /\sps2exe\.ps1/ nocase ascii wide
                        $string4_redpill_greyware_tool_keyword = /\.ps1\s\-sysinfo\sEnum/ nocase ascii wide
                        $string5_redpill_greyware_tool_keyword = /\/ps2exe\.ps1/ nocase ascii wide
                        $string6_redpill_greyware_tool_keyword = /\/vbs2exe\.exe/ nocase ascii wide
                        $string7_redpill_greyware_tool_keyword = /\\credentials\.log/ nocase ascii wide
                        $string8_redpill_greyware_tool_keyword = /\\Get\-AVStatus\.ps1/ nocase ascii wide
                        $string9_redpill_greyware_tool_keyword = /\\ksjjhav\.log/ nocase ascii wide
                        $string10_redpill_greyware_tool_keyword = /\\list\-recycle\-bin\.ps1/ nocase ascii wide
                        $string11_redpill_greyware_tool_keyword = /\\OutlookEmails\.log/ nocase ascii wide
                        $string12_redpill_greyware_tool_keyword = /\\ps2exe\.ps1/ nocase ascii wide
                        $string13_redpill_greyware_tool_keyword = /\\Screenshot\.exe\s/ nocase ascii wide
                        $string14_redpill_greyware_tool_keyword = /\\Screenshot\.ps1/ nocase ascii wide
                        $string15_redpill_greyware_tool_keyword = /\\Temp\\clipboard\.log/ nocase ascii wide
                        $string16_redpill_greyware_tool_keyword = /\\Temp\\dave\.log/ nocase ascii wide
                        $string17_redpill_greyware_tool_keyword = /\\Temp\\fsdgss\.log/ nocase ascii wide
                        $string18_redpill_greyware_tool_keyword = /\\vbs2exe\.exe/ nocase ascii wide
                        $string19_redpill_greyware_tool_keyword = /BATtoEXEconverter\.bat/ nocase ascii wide
                        $string20_redpill_greyware_tool_keyword = /identify_offensive_tools\.ps1/ nocase ascii wide
                        $string21_redpill_greyware_tool_keyword = /Mitre\-T1202\.ps1/ nocase ascii wide
                        $string22_redpill_greyware_tool_keyword = /Temp\\iprange\.log/ nocase ascii wide
                        $string23_redpill_greyware_tool_keyword = /vbs2exe\.exe\s/ nocase ascii wide

    condition:
        any of them
}