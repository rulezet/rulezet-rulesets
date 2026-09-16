rule adcshunter
{
    meta:
        description = "Detection patterns for the tool 'adcshunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adcshunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/adcshunter\.git/ nocase ascii wide
                        $string2 = "ADCS Server location identified on IP " nocase ascii wide
                        $string3 = /adcshunter\.py/ nocase ascii wide
                        $string4 = "danti1988/adcshunter" nocase ascii wide
                        $string5 = "impacket-rpcdump" nocase ascii wide
                        $string6 = /rpcdump\.py/ nocase ascii wide
                        $string7 = /Vulnerable\sWeb\sEnrollment\sendpoint\sidentified\:\shttp\:\/\/.{0,1000}\/certsrv\/certsnsh\.asp/ nocase ascii wide

    condition:
        any of them
}