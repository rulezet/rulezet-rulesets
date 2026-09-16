rule SeeYouCM_Thief
{
    meta:
        description = "Detection patterns for the tool 'SeeYouCM-Thief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SeeYouCM-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sthief\.py/ nocase ascii wide
                        $string2 = "/SeeYouCM-Thief" nocase ascii wide
                        $string3 = /\/thief\.py/ nocase ascii wide
                        $string4 = /cisco\-phone\-query\.sh/ nocase ascii wide
                        $string5 = "Credentials Found in Configurations!" nocase ascii wide
                        $string6 = /python.{0,1000}http\:\/\/.{0,1000}\:6970\/ConfigFileCacheList\.txt/ nocase ascii wide
                        $string7 = /python.{0,1000}\'http\:\/\/.{0,1000}SEP.{0,1000}\:6970\/.{0,1000}\.cnf\.xml/ nocase ascii wide
                        $string8 = /python.{0,1000}https\:\/\/.{0,1000}\:8443\/cucm\-uds\/users\?name\=/ nocase ascii wide
                        $string9 = "run thief:latest" nocase ascii wide
                        $string10 = /search_for_secrets\(/ nocase ascii wide
                        $string11 = /SeeYouCM\-Thief\.git/ nocase ascii wide
                        $string12 = "SeeYouCM-Thief-main" nocase ascii wide
                        $string13 = /thief\.py\s\-/ nocase ascii wide
                        $string14 = /tmp.{0,1000}ciscophones\.tgz/ nocase ascii wide

    condition:
        any of them
}