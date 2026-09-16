rule rule_hakrawler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hakrawler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hakrawler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hakrawler_offensive_tool_keyword = "/bin/hakrawler"
                        $string2_hakrawler_offensive_tool_keyword = /\/hakrawler\.git/
                        $string3_hakrawler_offensive_tool_keyword = /\|\shakrawler/
                        $string4_hakrawler_offensive_tool_keyword = "hakluke/hakrawler"
                        $string5_hakrawler_offensive_tool_keyword = "hakrawler -"
                        $string6_hakrawler_offensive_tool_keyword = /hakrawler\.go/
                        $string7_hakrawler_offensive_tool_keyword = "hakrawler@latest"
                        $string8_hakrawler_offensive_tool_keyword = "hakrawler-master"
                        $string9_hakrawler_offensive_tool_keyword = "haktrails subdomains"
                        $string10_hakrawler_offensive_tool_keyword = "install hakrawler"

    condition:
        any of them
}