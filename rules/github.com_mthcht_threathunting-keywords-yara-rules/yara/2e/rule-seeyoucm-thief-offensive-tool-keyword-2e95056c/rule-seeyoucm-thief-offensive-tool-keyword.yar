rule rule_SeeYouCM_Thief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SeeYouCM-Thief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SeeYouCM-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SeeYouCM_Thief_offensive_tool_keyword = /\sthief\.py/ nocase ascii wide
                        $string2_SeeYouCM_Thief_offensive_tool_keyword = "/SeeYouCM-Thief" nocase ascii wide
                        $string3_SeeYouCM_Thief_offensive_tool_keyword = /\/thief\.py/ nocase ascii wide
                        $string4_SeeYouCM_Thief_offensive_tool_keyword = /cisco\-phone\-query\.sh/ nocase ascii wide
                        $string5_SeeYouCM_Thief_offensive_tool_keyword = "Credentials Found in Configurations!" nocase ascii wide
                        $string6_SeeYouCM_Thief_offensive_tool_keyword = /python.{0,1000}http\:\/\/.{0,1000}\:6970\/ConfigFileCacheList\.txt/ nocase ascii wide
                        $string7_SeeYouCM_Thief_offensive_tool_keyword = /python.{0,1000}\'http\:\/\/.{0,1000}SEP.{0,1000}\:6970\/.{0,1000}\.cnf\.xml/ nocase ascii wide
                        $string8_SeeYouCM_Thief_offensive_tool_keyword = /python.{0,1000}https\:\/\/.{0,1000}\:8443\/cucm\-uds\/users\?name\=/ nocase ascii wide
                        $string9_SeeYouCM_Thief_offensive_tool_keyword = "run thief:latest" nocase ascii wide
                        $string10_SeeYouCM_Thief_offensive_tool_keyword = /search_for_secrets\(/ nocase ascii wide
                        $string11_SeeYouCM_Thief_offensive_tool_keyword = /SeeYouCM\-Thief\.git/ nocase ascii wide
                        $string12_SeeYouCM_Thief_offensive_tool_keyword = "SeeYouCM-Thief-main" nocase ascii wide
                        $string13_SeeYouCM_Thief_offensive_tool_keyword = /thief\.py\s\-/ nocase ascii wide
                        $string14_SeeYouCM_Thief_offensive_tool_keyword = /tmp.{0,1000}ciscophones\.tgz/ nocase ascii wide

    condition:
        any of them
}