rule rule_undertheradar_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'undertheradar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "undertheradar"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_undertheradar_offensive_tool_keyword = /\.\\dumpy\.py/ nocase ascii wide
                        $string2_undertheradar_offensive_tool_keyword = /\/undertheradar\.git/ nocase ascii wide
                        $string3_undertheradar_offensive_tool_keyword = /\\public\\klogging\.log/ nocase ascii wide
                        $string4_undertheradar_offensive_tool_keyword = /\\users\\public\\sam\.save/ nocase ascii wide
                        $string5_undertheradar_offensive_tool_keyword = /\\users\\public\\system\.save/ nocase ascii wide
                        $string6_undertheradar_offensive_tool_keyword = /c\:\/users\/public\/creds\.log/ nocase ascii wide
                        $string7_undertheradar_offensive_tool_keyword = /c\:\\users\\public\\creds\.log/ nocase ascii wide
                        $string8_undertheradar_offensive_tool_keyword = /c\:\\users\\public\\output\.txt/ nocase ascii wide
                        $string9_undertheradar_offensive_tool_keyword = "g3tsyst3m/undertheradar" nocase ascii wide
                        $string10_undertheradar_offensive_tool_keyword = /simplekeylogger\./ nocase ascii wide
                        $string11_undertheradar_offensive_tool_keyword = "Successfully dumped SAM and SYSTEM" nocase ascii wide
                        $string12_undertheradar_offensive_tool_keyword = "undertheradar-main" nocase ascii wide
                        $string13_undertheradar_offensive_tool_keyword = /users\/public\/troubleshooting_log\.log/ nocase ascii wide

    condition:
        any of them
}