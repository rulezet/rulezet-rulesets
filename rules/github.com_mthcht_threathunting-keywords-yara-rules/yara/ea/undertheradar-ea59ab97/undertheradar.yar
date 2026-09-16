rule undertheradar
{
    meta:
        description = "Detection patterns for the tool 'undertheradar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "undertheradar"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\\dumpy\.py/ nocase ascii wide
                        $string2 = /\/undertheradar\.git/ nocase ascii wide
                        $string3 = /\\public\\klogging\.log/ nocase ascii wide
                        $string4 = /\\users\\public\\sam\.save/ nocase ascii wide
                        $string5 = /\\users\\public\\system\.save/ nocase ascii wide
                        $string6 = /c\:\/users\/public\/creds\.log/ nocase ascii wide
                        $string7 = /c\:\\users\\public\\creds\.log/ nocase ascii wide
                        $string8 = /c\:\\users\\public\\output\.txt/ nocase ascii wide
                        $string9 = "g3tsyst3m/undertheradar" nocase ascii wide
                        $string10 = /simplekeylogger\./ nocase ascii wide
                        $string11 = "Successfully dumped SAM and SYSTEM" nocase ascii wide
                        $string12 = "undertheradar-main" nocase ascii wide
                        $string13 = /users\/public\/troubleshooting_log\.log/ nocase ascii wide

    condition:
        any of them
}