rule rule_teamsphisher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'teamsphisher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamsphisher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_teamsphisher_offensive_tool_keyword = /\s\-\-greeting\s.{0,1000}\s\-\-personalize\s.{0,1000}\-\-securelink/ nocase ascii wide
                        $string2_teamsphisher_offensive_tool_keyword = /\/Teamphisher\.txt/ nocase ascii wide
                        $string3_teamsphisher_offensive_tool_keyword = /\/Teamphisher\/targets\.txt/ nocase ascii wide
                        $string4_teamsphisher_offensive_tool_keyword = /best.{0,1000}phish\sher/ nocase ascii wide
                        $string5_teamsphisher_offensive_tool_keyword = /myreallycooltotallyrealtenant\.onmicrosoft\.com/ nocase ascii wide
                        $string6_teamsphisher_offensive_tool_keyword = "Octoberfest7/TeamsPhisher" nocase ascii wide
                        $string7_teamsphisher_offensive_tool_keyword = /TeamsPhisher\.git/ nocase ascii wide
                        $string8_teamsphisher_offensive_tool_keyword = /teamsphisher\.log/ nocase ascii wide
                        $string9_teamsphisher_offensive_tool_keyword = /teamsphisher\.py/ nocase ascii wide
                        $string10_teamsphisher_offensive_tool_keyword = /TeamsPhisher\-main\.zip/ nocase ascii wide

    condition:
        any of them
}