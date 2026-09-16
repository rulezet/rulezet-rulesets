rule WPScan
{
    meta:
        description = "Detection patterns for the tool 'WPScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WPScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/\.wpscan\//
                        $string2 = "wpscan --url "
                        $string3 = "wpscanteam/tap/wpscan"
                        $string4 = "wpscanteam/wpscan"

    condition:
        any of them
}