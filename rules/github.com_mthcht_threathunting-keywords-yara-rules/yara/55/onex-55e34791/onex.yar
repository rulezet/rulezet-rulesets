rule onex
{
    meta:
        description = "Detection patterns for the tool 'onex' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onex"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/onex\.git/ nocase ascii wide
                        $string2 = "cube0x0/MiniDump" nocase ascii wide
                        $string3 = /minidump\..{0,1000}\slsass\.dmp/ nocase ascii wide
                        $string4 = /procdump.{0,1000}\slsass\.exe\s.{0,1000}\.dmp/ nocase ascii wide
                        $string5 = "rajkumardusad/onex" nocase ascii wide
                        $string6 = "onex install " nocase ascii wide

    condition:
        any of them
}