rule poc
{
    meta:
        description = "Detection patterns for the tool 'poc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sRCE\.py\s\-/ nocase ascii wide
                        $string2 = /\/CVE\-.{0,1000}_EXPLOIT_0DAY\// nocase ascii wide
                        $string3 = "/Hashi0x/" nocase ascii wide
                        $string4 = /\/ka7ana\/CVE.{0,1000}\.ps1/ nocase ascii wide
                        $string5 = "/MsgKitTestTool/" nocase ascii wide
                        $string6 = "/PoC-CVE-2023-21554" nocase ascii wide
                        $string7 = "/sqrtZeroKnowledge/CVE-" nocase ascii wide
                        $string8 = /\/Trackflaw\/CVE.{0,1000}\.py/ nocase ascii wide
                        $string9 = /cve\-2023\-21554\.nse/ nocase ascii wide

    condition:
        any of them
}