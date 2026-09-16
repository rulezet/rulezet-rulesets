rule rule_adcshunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adcshunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adcshunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adcshunter_offensive_tool_keyword = /\/adcshunter\.git/ nocase ascii wide
                        $string2_adcshunter_offensive_tool_keyword = "ADCS Server location identified on IP " nocase ascii wide
                        $string3_adcshunter_offensive_tool_keyword = /adcshunter\.py/ nocase ascii wide
                        $string4_adcshunter_offensive_tool_keyword = "danti1988/adcshunter" nocase ascii wide
                        $string5_adcshunter_offensive_tool_keyword = "impacket-rpcdump" nocase ascii wide
                        $string6_adcshunter_offensive_tool_keyword = /rpcdump\.py/ nocase ascii wide
                        $string7_adcshunter_offensive_tool_keyword = /Vulnerable\sWeb\sEnrollment\sendpoint\sidentified\:\shttp\:\/\/.{0,1000}\/certsrv\/certsnsh\.asp/ nocase ascii wide

    condition:
        any of them
}