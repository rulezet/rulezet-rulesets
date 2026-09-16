rule rule_WPScan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WPScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WPScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WPScan_offensive_tool_keyword = /\/\.wpscan\//
                        $string2_WPScan_offensive_tool_keyword = "wpscan --url "
                        $string3_WPScan_offensive_tool_keyword = "wpscanteam/tap/wpscan"
                        $string4_WPScan_offensive_tool_keyword = "wpscanteam/wpscan"

    condition:
        any of them
}