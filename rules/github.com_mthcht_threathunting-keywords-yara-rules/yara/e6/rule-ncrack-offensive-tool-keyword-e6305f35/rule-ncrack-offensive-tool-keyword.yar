rule rule_ncrack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ncrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ncrack_offensive_tool_keyword = "/ncrack-"
                        $string2_ncrack_offensive_tool_keyword = /\/ncrack\.git/ nocase ascii wide
                        $string3_ncrack_offensive_tool_keyword = /ncrack\-.{0,1000}\.dmg/ nocase ascii wide
                        $string4_ncrack_offensive_tool_keyword = /ncrack\-.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string5_ncrack_offensive_tool_keyword = /ncrack\.exe/ nocase ascii wide
                        $string6_ncrack_offensive_tool_keyword = /NcrackInstaller\.exe/ nocase ascii wide
                        $string7_ncrack_offensive_tool_keyword = /ncrack\-master\.zip/ nocase ascii wide
                        $string8_ncrack_offensive_tool_keyword = "ncrack-services" nocase ascii wide
                        $string9_ncrack_offensive_tool_keyword = "nmap/ncrack" nocase ascii wide

    condition:
        any of them
}