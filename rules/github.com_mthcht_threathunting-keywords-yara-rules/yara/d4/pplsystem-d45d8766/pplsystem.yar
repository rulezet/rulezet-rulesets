rule PPLSystem
{
    meta:
        description = "Detection patterns for the tool 'PPLSystem' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLSystem"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-\-dll\s.{0,1000}\s\-\-dump\s.{0,1000}\s\-\-pid\s/ nocase ascii wide
                        $string2 = /\/pplsystem\.exe/ nocase ascii wide
                        $string3 = /\/PPLSystem\.git/ nocase ascii wide
                        $string4 = /\[\+\]\sRemote\sCOM\ssecret\s\:\s/ nocase ascii wide
                        $string5 = /\\pplsystem\.exe/ nocase ascii wide
                        $string6 = /\\PPLSystem\-main/ nocase ascii wide
                        $string7 = "531870bd9f59ac799dfa6573472db1966cd3a9f8ece84d2f2e409e4384770b4a" nocase ascii wide
                        $string8 = /Live\sDump\sCapture\sDump\sData\sAPI\sended\.\sNT\sStatus\:\sSTATUS_SUCCESS\./ nocase ascii wide
                        $string9 = /pplsystem\.exe\s/ nocase ascii wide
                        $string10 = "Slowerzs/PPLSystem" nocase ascii wide

    condition:
        any of them
}