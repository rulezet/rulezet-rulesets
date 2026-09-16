rule rule_chromedump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chromedump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromedump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chromedump_offensive_tool_keyword = "/ChromeDump/" nocase ascii wide
                        $string2_chromedump_offensive_tool_keyword = /\/dumpweb\.log/
                        $string3_chromedump_offensive_tool_keyword = /ChromeDump\.git/ nocase ascii wide
                        $string4_chromedump_offensive_tool_keyword = /chromedump\.py/ nocase ascii wide
                        $string5_chromedump_offensive_tool_keyword = /ChromeDump\-main\.zip/ nocase ascii wide

    condition:
        any of them
}