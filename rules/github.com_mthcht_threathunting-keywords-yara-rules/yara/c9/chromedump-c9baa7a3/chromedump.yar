rule chromedump
{
    meta:
        description = "Detection patterns for the tool 'chromedump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromedump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ChromeDump/" nocase ascii wide
                        $string2 = /\/dumpweb\.log/
                        $string3 = /ChromeDump\.git/ nocase ascii wide
                        $string4 = /chromedump\.py/ nocase ascii wide
                        $string5 = /ChromeDump\-main\.zip/ nocase ascii wide

    condition:
        any of them
}