rule rule_onex_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'onex' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onex"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_onex_offensive_tool_keyword = /\/onex\.git/ nocase ascii wide
                        $string2_onex_offensive_tool_keyword = "cube0x0/MiniDump" nocase ascii wide
                        $string3_onex_offensive_tool_keyword = /minidump\..{0,1000}\slsass\.dmp/ nocase ascii wide
                        $string4_onex_offensive_tool_keyword = /procdump.{0,1000}\slsass\.exe\s.{0,1000}\.dmp/ nocase ascii wide
                        $string5_onex_offensive_tool_keyword = "rajkumardusad/onex" nocase ascii wide
                        $string6_onex_offensive_tool_keyword = "onex install " nocase ascii wide

    condition:
        any of them
}