rule rule_GCR_Google_Calendar_RAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GCR-Google-Calendar-RAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GCR-Google-Calendar-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GCR_Google_Calendar_RAT_offensive_tool_keyword = /\.\/gcr\.py/
                        $string2_GCR_Google_Calendar_RAT_offensive_tool_keyword = "GCR - Google Calendar RAT" nocase ascii wide
                        $string3_GCR_Google_Calendar_RAT_offensive_tool_keyword = "GCR-Google-Calendar-RAT" nocase ascii wide
                        $string4_GCR_Google_Calendar_RAT_offensive_tool_keyword = /main\/gcr\.py/ nocase ascii wide
                        $string5_GCR_Google_Calendar_RAT_offensive_tool_keyword = /python3\sgcr\.py/ nocase ascii wide

    condition:
        any of them
}