rule rule_Cam_Hackers_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cam-Hackers' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cam-Hackers"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cam_Hackers_offensive_tool_keyword = /\/Cam\-Hackers\.git/ nocase ascii wide
                        $string2_Cam_Hackers_offensive_tool_keyword = "AngelSecurityTeam/Cam-Hackers" nocase ascii wide
                        $string3_Cam_Hackers_offensive_tool_keyword = /cam\-hackers\.py/ nocase ascii wide
                        $string4_Cam_Hackers_offensive_tool_keyword = /Cam\-Hackers\-master\.zip/ nocase ascii wide
                        $string5_Cam_Hackers_offensive_tool_keyword = /http\:\/\/www\.insecam\.org\/en\/jsoncountries\// nocase ascii wide

    condition:
        any of them
}