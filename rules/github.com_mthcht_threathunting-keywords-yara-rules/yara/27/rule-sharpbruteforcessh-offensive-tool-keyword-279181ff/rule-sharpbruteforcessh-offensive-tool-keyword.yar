rule rule_SharpBruteForceSSH_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpBruteForceSSH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBruteForceSSH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpBruteForceSSH_offensive_tool_keyword = /\/SharpBruteForceSSH\.git/ nocase ascii wide
                        $string2_SharpBruteForceSSH_offensive_tool_keyword = /\\SharpBruteForceSSH\-main/ nocase ascii wide
                        $string3_SharpBruteForceSSH_offensive_tool_keyword = "2f3c1b3378d19418aa4c99685f3ab9d6730c132a920946b64c0e4edc9efd5ed6" nocase ascii wide
                        $string4_SharpBruteForceSSH_offensive_tool_keyword = "4775208998622726a1b1a5f156e6e88b2ba4e568416795c19358d7380c35b0b8" nocase ascii wide
                        $string5_SharpBruteForceSSH_offensive_tool_keyword = "9ec223a7538868ec25a3823217038beedef36d8dd1f8e388c056bf79fd864b93" nocase ascii wide
                        $string6_SharpBruteForceSSH_offensive_tool_keyword = "Brute forcing passwords for " nocase ascii wide
                        $string7_SharpBruteForceSSH_offensive_tool_keyword = "Dictionary brute force attack on SSH services" nocase ascii wide
                        $string8_SharpBruteForceSSH_offensive_tool_keyword = "f0b1a06aa6d5ea27814565755c6bfe2520dd71c4df02768fe7d621c3c3d0db75" nocase ascii wide
                        $string9_SharpBruteForceSSH_offensive_tool_keyword = "HernanRodriguez1/SharpBruteForceSSH" nocase ascii wide
                        $string10_SharpBruteForceSSH_offensive_tool_keyword = /SharpBruteForceSSH\.cs/ nocase ascii wide
                        $string11_SharpBruteForceSSH_offensive_tool_keyword = /SharpBruteForceSSH\.exe/ nocase ascii wide
                        $string12_SharpBruteForceSSH_offensive_tool_keyword = /sshBruteForce\.exe/ nocase ascii wide

    condition:
        any of them
}