rule nopaste_net
{
    meta:
        description = "Detection patterns for the tool 'nopaste.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nopaste.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /curl.{0,1000}nopaste\.net/
                        $string2 = /docker\srun\s.{0,1000}\/\.config\/pcopy/
                        $string3 = /https\:\/\/nopaste\.net\// nocase ascii wide
                        $string4 = /IEX.{0,1000}nopaste\.net/ nocase ascii wide
                        $string5 = /IWR.{0,1000}nopaste\.net/ nocase ascii wide
                        $string6 = /nc\s\-N\snopaste\.net\s/
                        $string7 = /nopaste\.net.{0,1000}IWR/ nocase ascii wide

    condition:
        any of them
}