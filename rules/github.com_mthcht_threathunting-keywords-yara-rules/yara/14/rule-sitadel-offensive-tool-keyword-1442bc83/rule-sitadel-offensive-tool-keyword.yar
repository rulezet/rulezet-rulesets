rule rule_Sitadel_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sitadel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sitadel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sitadel_offensive_tool_keyword = " -a bruteforce " nocase ascii wide
                        $string2_Sitadel_offensive_tool_keyword = " --attack bruteforce" nocase ascii wide
                        $string3_Sitadel_offensive_tool_keyword = " --attack injection" nocase ascii wide
                        $string4_Sitadel_offensive_tool_keyword = " --attack vulns " nocase ascii wide
                        $string5_Sitadel_offensive_tool_keyword = /\ssitadel\.py/ nocase ascii wide
                        $string6_Sitadel_offensive_tool_keyword = /\/Sitadel\.git/ nocase ascii wide
                        $string7_Sitadel_offensive_tool_keyword = /\/sitadel\.log/ nocase ascii wide
                        $string8_Sitadel_offensive_tool_keyword = /\/sitadel\.py/ nocase ascii wide
                        $string9_Sitadel_offensive_tool_keyword = /\\sitadel\.log/ nocase ascii wide
                        $string10_Sitadel_offensive_tool_keyword = "docker run sitadel" nocase ascii wide
                        $string11_Sitadel_offensive_tool_keyword = "python3 sitadel" nocase ascii wide
                        $string12_Sitadel_offensive_tool_keyword = "sitadel http://" nocase ascii wide
                        $string13_Sitadel_offensive_tool_keyword = "sitadel https://" nocase ascii wide
                        $string14_Sitadel_offensive_tool_keyword = /sitadel\.py\s/ nocase ascii wide
                        $string15_Sitadel_offensive_tool_keyword = /Sitadel\-master\.zip/ nocase ascii wide

    condition:
        any of them
}