rule ncrack
{
    meta:
        description = "Detection patterns for the tool 'ncrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ncrack-"
                        $string2 = /\/ncrack\.git/ nocase ascii wide
                        $string3 = /ncrack\-.{0,1000}\.dmg/ nocase ascii wide
                        $string4 = /ncrack\-.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string5 = /ncrack\.exe/ nocase ascii wide
                        $string6 = /NcrackInstaller\.exe/ nocase ascii wide
                        $string7 = /ncrack\-master\.zip/ nocase ascii wide
                        $string8 = "ncrack-services" nocase ascii wide
                        $string9 = "nmap/ncrack" nocase ascii wide

    condition:
        any of them
}