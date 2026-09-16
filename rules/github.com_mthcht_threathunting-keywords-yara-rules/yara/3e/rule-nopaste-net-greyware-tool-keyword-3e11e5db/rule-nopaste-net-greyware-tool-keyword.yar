rule rule_nopaste_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nopaste.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nopaste.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nopaste_net_greyware_tool_keyword = /curl.{0,1000}nopaste\.net/
                        $string2_nopaste_net_greyware_tool_keyword = /docker\srun\s.{0,1000}\/\.config\/pcopy/
                        $string3_nopaste_net_greyware_tool_keyword = /https\:\/\/nopaste\.net\// nocase ascii wide
                        $string4_nopaste_net_greyware_tool_keyword = /IEX.{0,1000}nopaste\.net/ nocase ascii wide
                        $string5_nopaste_net_greyware_tool_keyword = /IWR.{0,1000}nopaste\.net/ nocase ascii wide
                        $string6_nopaste_net_greyware_tool_keyword = /nc\s\-N\snopaste\.net\s/
                        $string7_nopaste_net_greyware_tool_keyword = /nopaste\.net.{0,1000}IWR/ nocase ascii wide

    condition:
        any of them
}