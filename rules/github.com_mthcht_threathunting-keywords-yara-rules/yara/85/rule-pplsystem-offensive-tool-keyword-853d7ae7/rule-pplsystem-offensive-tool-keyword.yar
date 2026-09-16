rule rule_PPLSystem_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PPLSystem' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLSystem"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PPLSystem_offensive_tool_keyword = /\.exe\s\-\-dll\s.{0,1000}\s\-\-dump\s.{0,1000}\s\-\-pid\s/ nocase ascii wide
                        $string2_PPLSystem_offensive_tool_keyword = /\/pplsystem\.exe/ nocase ascii wide
                        $string3_PPLSystem_offensive_tool_keyword = /\/PPLSystem\.git/ nocase ascii wide
                        $string4_PPLSystem_offensive_tool_keyword = /\[\+\]\sRemote\sCOM\ssecret\s\:\s/ nocase ascii wide
                        $string5_PPLSystem_offensive_tool_keyword = /\\pplsystem\.exe/ nocase ascii wide
                        $string6_PPLSystem_offensive_tool_keyword = /\\PPLSystem\-main/ nocase ascii wide
                        $string7_PPLSystem_offensive_tool_keyword = "531870bd9f59ac799dfa6573472db1966cd3a9f8ece84d2f2e409e4384770b4a" nocase ascii wide
                        $string8_PPLSystem_offensive_tool_keyword = /Live\sDump\sCapture\sDump\sData\sAPI\sended\.\sNT\sStatus\:\sSTATUS_SUCCESS\./ nocase ascii wide
                        $string9_PPLSystem_offensive_tool_keyword = /pplsystem\.exe\s/ nocase ascii wide
                        $string10_PPLSystem_offensive_tool_keyword = "Slowerzs/PPLSystem" nocase ascii wide

    condition:
        any of them
}