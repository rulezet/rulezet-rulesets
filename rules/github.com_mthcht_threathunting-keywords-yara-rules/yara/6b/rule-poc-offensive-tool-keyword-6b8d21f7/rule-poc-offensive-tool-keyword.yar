rule rule_poc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'poc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_poc_offensive_tool_keyword = /\sRCE\.py\s\-/ nocase ascii wide
                        $string2_poc_offensive_tool_keyword = /\/CVE\-.{0,1000}_EXPLOIT_0DAY\// nocase ascii wide
                        $string3_poc_offensive_tool_keyword = "/Hashi0x/" nocase ascii wide
                        $string4_poc_offensive_tool_keyword = /\/ka7ana\/CVE.{0,1000}\.ps1/ nocase ascii wide
                        $string5_poc_offensive_tool_keyword = "/MsgKitTestTool/" nocase ascii wide
                        $string6_poc_offensive_tool_keyword = "/PoC-CVE-2023-21554" nocase ascii wide
                        $string7_poc_offensive_tool_keyword = "/sqrtZeroKnowledge/CVE-" nocase ascii wide
                        $string8_poc_offensive_tool_keyword = /\/Trackflaw\/CVE.{0,1000}\.py/ nocase ascii wide
                        $string9_poc_offensive_tool_keyword = /cve\-2023\-21554\.nse/ nocase ascii wide

    condition:
        any of them
}