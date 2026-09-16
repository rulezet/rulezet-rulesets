rule icacls
{
    meta:
        description = "Detection patterns for the tool 'icacls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icacls"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /icacls\s\\"\%appdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string2 = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string3 = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide
                        $string4 = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string5 = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide
                        $string6 = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
                        $string7 = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide

    condition:
        any of them
}