rule rule_icacls_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'icacls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icacls"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_icacls_greyware_tool_keyword = /icacls\s\\"\%appdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string2_icacls_greyware_tool_keyword = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string3_icacls_greyware_tool_keyword = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide
                        $string4_icacls_greyware_tool_keyword = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string5_icacls_greyware_tool_keyword = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide
                        $string6_icacls_greyware_tool_keyword = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string7_icacls_greyware_tool_keyword = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide

    condition:
        any of them
}