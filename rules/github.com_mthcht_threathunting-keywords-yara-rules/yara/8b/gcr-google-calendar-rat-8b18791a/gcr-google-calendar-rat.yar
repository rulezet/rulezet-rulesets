rule GCR_Google_Calendar_RAT
{
    meta:
        description = "Detection patterns for the tool 'GCR-Google-Calendar-RAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GCR-Google-Calendar-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/gcr\.py/
                        $string2 = "GCR - Google Calendar RAT" nocase ascii wide
                        $string3 = "GCR-Google-Calendar-RAT" nocase ascii wide
                        $string4 = /main\/gcr\.py/ nocase ascii wide
                        $string5 = /python3\sgcr\.py/ nocase ascii wide

    condition:
        any of them
}