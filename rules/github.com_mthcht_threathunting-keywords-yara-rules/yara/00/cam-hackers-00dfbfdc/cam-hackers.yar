rule Cam_Hackers
{
    meta:
        description = "Detection patterns for the tool 'Cam-Hackers' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cam-Hackers"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Cam\-Hackers\.git/ nocase ascii wide
                        $string2 = "AngelSecurityTeam/Cam-Hackers" nocase ascii wide
                        $string3 = /cam\-hackers\.py/ nocase ascii wide
                        $string4 = /Cam\-Hackers\-master\.zip/ nocase ascii wide
                        $string5 = /http\:\/\/www\.insecam\.org\/en\/jsoncountries\// nocase ascii wide

    condition:
        any of them
}